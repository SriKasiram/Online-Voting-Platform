"""
SR-20: AES-256-encrypted, tamper-evident backups of the whole database, restored only into a
separate database, and the recovery test that proves a backup restores within 30 minutes with no
accepted ballot lost and every ballot confirmation reference (its receipt hash) reconciled.

The restore database is <test database>_restore (evoting_test_restore), created here if missing
and emptied before and after each test. These tests are never skipped: if the database user cannot
create it, they fail and say what to run.
"""

import base64
import datetime as dt
import decimal
import hashlib
import json
import os
import re
import shutil
import stat
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Column, Engine, Numeric, create_engine, func, inspect, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from test_sr17_count import CountedElection

from app.ballot_chain import checkpoint_file, verify_chain
from app.config import BACKEND_DIR, Settings, settings
from app.db import Base
from app.models import AuditLogEntry
from app.security import verify_audit_chain
from app.stores import BALLOT_TABLES, IDENTITY_TABLES
from scripts import backup_common, backup_db, gen_backup_key, recovery_test, restore_db
from scripts.backup_common import (
    BALLOT_FILE,
    ENCRYPTED,
    IDENTITY_FILE,
    MANIFEST,
    BackupRefused,
    application_tables,
    decode_value,
    decrypt_payload,
    encode_value,
    encrypt_payload,
    load_backup_key,
    reset_target,
    target_is_empty,
)
from scripts.backup_db import take_backup
from scripts.gen_backup_key import generate_backup_key
from scripts.recovery_test import run_checks
from scripts.restore_db import restore

RESTORE_DB = f"{settings.postgres_test_db}_restore"
TRIGGERS = {"ballots_append_only", "ballot_chain_append_only", "audit_log_append_only"}


# ---------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------


@pytest.fixture(scope="session")
def restore_url(engine: Engine) -> str:
    """SR-20: the restore database, created once if it is missing. A clear failure, never a skip, if it cannot be."""
    try:
        admin = create_engine(settings.database_url("postgres"), isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as connection:
                if not connection.scalar(text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": RESTORE_DB}):
                    connection.execute(text(f'CREATE DATABASE "{RESTORE_DB}"'))
        finally:
            admin.dispose()
    except SQLAlchemyError as problem:
        pytest.fail(
            f"SR-20: the backup tests need a database named {RESTORE_DB}, and {settings.postgres_user} could not create it "
            f"({type(problem).__name__}). As a PostgreSQL superuser, run once: "
            f"CREATE DATABASE {RESTORE_DB} OWNER {settings.postgres_user};",
            pytrace=False,
        )
    return settings.database_url(RESTORE_DB).render_as_string(hide_password=False)


@pytest.fixture
def target(restore_url: str, engine: Engine) -> Iterator[str]:
    """SR-20: the restore database, empty at the start and the end of each test."""

    def empty() -> None:
        try:
            reset_target(restore_url, engine.url)
        except BackupRefused as refused:
            pytest.fail(
                f"SR-20: {refused}. As a PostgreSQL superuser, run once: ALTER DATABASE {RESTORE_DB} OWNER TO {settings.postgres_user};",
                pytrace=False,
            )

    empty()
    yield restore_url
    empty()


@pytest.fixture
def target_engine(target: str) -> Iterator[Engine]:
    restored = create_engine(target, hide_parameters=True)
    yield restored
    restored.dispose()


@pytest.fixture
def backup_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    """SR-20: a temporary backup key, made by the key script's own function, with the settings pointed at it."""
    path = generate_backup_key(tmp_path / "keys" / "backup.key")
    monkeypatch.setattr(settings, "backup_key_file", path)
    return load_backup_key(path)


@pytest.fixture
def backups_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """SR-20: a temporary BACKUPS_DIR, never backend/backups/."""
    folder = tmp_path / "backups"
    monkeypatch.setattr(settings, "backups_dir", folder)
    return folder


@pytest.fixture
def scripts_on_test_db(monkeypatch: pytest.MonkeyPatch, engine: Engine, target: str, backup_key: bytes, backups_dir: Path) -> None:
    """SR-20: the command-line scripts, as run in backend/, but with the test database as the live one."""
    monkeypatch.setattr(settings, "postgres_db", settings.postgres_test_db)
    monkeypatch.setattr(settings, "restore_database_url", SecretStr(target))
    monkeypatch.setattr(backup_db, "engine", engine)
    monkeypatch.setattr(recovery_test, "engine", engine)


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------


def table_rows(db_engine: Engine, table) -> list[tuple]:
    """SR-20: a table as the database returns it (bytes, UUIDs, datetimes, JSON), independent of the backup's encoding."""
    with db_engine.connect() as connection:
        return [tuple(row) for row in connection.execute(select(table).order_by(*table.primary_key.columns))]


def writable_copy(folder: Path, destination: Path) -> Path:
    """SR-20: a copy of a backup to tamper with; the backup itself stays read-only and untouched."""
    shutil.copytree(folder, destination)
    for path in destination.iterdir():
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return destination


def edit_manifest(folder: Path, change: Callable[[dict], None]) -> None:
    path = folder / MANIFEST
    manifest = json.loads(path.read_text(encoding="utf-8"))
    change(manifest)
    path.write_text(json.dumps(manifest), encoding="utf-8")


def entry(manifest: dict, name: str) -> dict:
    return next(item for item in manifest["files"] if item["name"] == name)


def rehash(folder: Path, name: str) -> None:
    """SR-20: what someone who altered a file would also do: record its new SHA-256 in the manifest."""
    digest = hashlib.sha256((folder / name).read_bytes()).hexdigest()
    edit_manifest(folder, lambda manifest: entry(manifest, name).update(sha256=digest))


def refusal(folder: Path, target_url: str, live_url, key: bytes) -> str:
    with pytest.raises(BackupRefused) as refused:
        restore(folder, target_url, live_url, key)
    return refused.value.code


def head_revision() -> str:
    return ScriptDirectory.from_config(Config(str(BACKEND_DIR / "alembic.ini"))).get_current_head()


def decrypted(folder: Path, manifest: dict, key: bytes, name: str) -> list[dict]:
    blob = (folder / (name + ENCRYPTED)).read_bytes()
    return [json.loads(line) for line in decrypt_payload(key, manifest["backup_id"], name, blob).decode("utf-8").splitlines()]


# ---------------------------------------------------------------
# Encoding, tables and keys
# ---------------------------------------------------------------


def test_encoding_is_lossless_for_every_column_type() -> None:
    """SR-20: each value comes back from its JSON line with the same type and value, led by the column's type."""
    tables = Base.metadata.tables
    cases = [
        (tables["audit_log"].c.prev_hash, b"\x00\xff\x10binary"),
        (tables["ballots"].c.id, uuid.uuid4()),
        (tables["audit_log"].c.created_at, dt.datetime(2027, 5, 15, 8, 30, 1, 123456, tzinfo=dt.UTC)),
        (tables["elections"].c.polling_date, dt.date(2027, 5, 15)),
        (tables["elections"].c.status, next(iter(tables["elections"].c.status.type.enum_class))),
        (tables["accounts"].c.username, "Elector.One"),
        (tables["accounts"].c.totp_last_step, 2**40),
        (tables["ballot_tokens"].c.consumed, True),
        # SR-20: a JSON value that looks like a tag stays exactly as it was
        (tables["audit_log"].c.details, {"$b64": "not a tag", "list": [1, 2.5, None, "x"]}),
        (Column("amount", Numeric), decimal.Decimal("12.3400")),
        (tables["audit_log"].c.details, None),
    ]
    for column, value in cases:
        back = decode_value(column, json.loads(json.dumps(encode_value(value))))
        assert (type(back), back) == (type(value), value), column


def test_every_application_table_is_backed_up_on_one_side() -> None:
    """SR-20: all tables of the models except alembic_version, each on exactly one SR-12 side."""
    names = {table.name for table in application_tables()}

    assert names == IDENTITY_TABLES | BALLOT_TABLES
    assert "alembic_version" not in names


def test_a_table_on_neither_side_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-20: a new table that has not chosen its SR-12 side stops the backup, instead of landing in a file by default."""
    monkeypatch.setattr(backup_common, "IDENTITY_TABLES", IDENTITY_TABLES - {"sessions"})

    with pytest.raises(BackupRefused) as refused:
        application_tables()

    assert refused.value.code == "table_without_side"


def test_backup_key_script_creates_a_separate_key_and_never_overwrites_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-20: 32 random bytes, refused if the key exists unless --force, and never the SR-11 ballot key file."""
    path = tmp_path / "keys" / "backup.key"
    monkeypatch.setattr(settings, "backup_key_file", path)

    assert gen_backup_key.main([]) == 0
    first = path.read_bytes()
    assert gen_backup_key.main([]) == 1
    assert path.read_bytes() == first
    assert gen_backup_key.main(["--force"]) == 0
    assert len(path.read_bytes()) == 32 and path.read_bytes() != first
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # SR-20: the default backup key is its own file, not the SR-11 ballot key
    assert BACKEND_DIR / Settings.model_fields["backup_key_file"].default != Settings.model_fields["ballot_key_file"].default


@pytest.mark.parametrize("content", [None, b"x" * 31, b"x" * 33, b""])
def test_a_missing_or_wrong_length_key_makes_backup_and_restore_refuse(
    content: bytes | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """SR-20: no key, or a key that is not 32 bytes, refuses both scripts before they touch any data."""
    path = tmp_path / "backup.key"
    if content is not None:
        path.write_bytes(content)
    monkeypatch.setattr(settings, "backup_key_file", path)
    monkeypatch.setattr(settings, "backups_dir", tmp_path / "backups")
    code = "backup_key_missing" if content is None else "backup_key_invalid"

    assert backup_db.main([]) == 1
    assert f"REFUSED: {code}" in capsys.readouterr().out
    assert not (tmp_path / "backups").exists()
    assert restore_db.main(["--backup", str(tmp_path)]) == 1
    assert f"REFUSED: {code}" in capsys.readouterr().out


def test_the_app_starts_without_the_backup_key_or_restore_database(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-20: only the backup scripts read the backup settings; the API and its health check do not need them."""
    monkeypatch.setattr(settings, "backup_key_file", tmp_path / "no-such.key")
    monkeypatch.setattr(settings, "restore_database_url", SecretStr(""))

    assert client.get("/api/health").status_code == 200
    for path in (BACKEND_DIR / "app").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert not re.search(r"^\s*(from|import) scripts\b", source, re.MULTILINE), path
        if path.name != "config.py":
            assert "backup_key" not in source and "restore_database_url" not in source, path


# ---------------------------------------------------------------
# Where a restore may go
# ---------------------------------------------------------------


def test_restore_refuses_an_empty_restore_url(tmp_path: Path, engine: Engine, backup_key: bytes) -> None:
    """SR-20: no RESTORE_DATABASE_URL, no restore and no recovery test."""
    assert refusal(tmp_path, "", engine.url, backup_key) == "no_restore_database"
    with pytest.raises(BackupRefused) as refused:
        recovery_test.recovery_test(engine, backup_key, tmp_path / "backups", "", engine.url, lambda: None, 1800)
    assert refused.value.code == "no_restore_database"
    assert not (tmp_path / "backups").exists()


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "LOCALHOST"])
def test_restore_refuses_the_live_database(host: str, tmp_path: Path, engine: Engine, backup_key: bytes) -> None:
    """SR-20: the same host, port and database as the live URL, however the local host is spelled, is refused."""
    live = engine.url.set(host=host).render_as_string(hide_password=False)

    assert refusal(tmp_path, live, engine.url, backup_key) == "target_is_live"
    with pytest.raises(BackupRefused) as refused:
        reset_target(live, engine.url)
    assert refused.value.code == "target_is_live"


def test_reset_target_refuses_a_name_without_restore(engine: Engine, backup_key: bytes, backups_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """SR-20: --reset-target empties only a database whose name ends with _restore, and refuses before any backup."""
    other = settings.database_url(f"{settings.postgres_test_db}_copy").render_as_string(hide_password=False)
    with pytest.raises(BackupRefused) as refused:
        reset_target(other, engine.url)
    assert refused.value.code == "reset_refused"

    monkeypatch.setattr(settings, "postgres_db", settings.postgres_test_db)
    monkeypatch.setattr(settings, "restore_database_url", SecretStr(other))
    monkeypatch.setattr(recovery_test, "engine", engine)
    assert recovery_test.main(["--reset-target"]) == 1
    assert "REFUSED: reset_refused" in capsys.readouterr().out
    assert not backups_dir.exists()


def test_an_unreachable_target_is_refused_with_a_reason(engine: Engine, backup_key: bytes, backups_dir: Path) -> None:
    """SR-20: a restore database that does not exist gives a reason code, never a traceback, and never shows the password."""
    done = take_backup(engine, backup_key, backups_dir)
    missing = settings.database_url(f"{settings.postgres_test_db}_missing_restore").render_as_string(hide_password=False)

    with pytest.raises(BackupRefused) as unreachable:
        restore(done.folder, missing, engine.url, backup_key)
    with pytest.raises(BackupRefused) as not_reset:
        reset_target(missing, engine.url)

    assert (unreachable.value.code, not_reset.value.code) == ("target_unreachable", "reset_failed")
    password = settings.postgres_password.get_secret_value()
    assert password not in str(unreachable.value) and password not in str(not_reset.value)


def test_restore_refuses_a_target_that_is_not_empty(engine: Engine, target: str, target_engine: Engine, backup_key: bytes, backups_dir: Path) -> None:
    """SR-20: any table at all, application or alembic_version, refuses the restore, and nothing there is dropped."""
    done = take_backup(engine, backup_key, backups_dir)
    with target_engine.begin() as connection:
        connection.execute(text("CREATE TABLE leftover (id integer)"))
    assert refusal(done.folder, target, engine.url, backup_key) == "target_not_empty"
    assert inspect(target_engine).get_table_names() == ["leftover"]

    with target_engine.begin() as connection:
        connection.execute(text("DROP TABLE leftover"))
        connection.execute(text("CREATE TABLE alembic_version (version_num varchar(32) PRIMARY KEY)"))
    assert refusal(done.folder, target, engine.url, backup_key) == "target_not_empty"


def test_restore_runs_the_migrations_at_the_manifest_revision(engine: Engine, target: str, target_engine: Engine, backup_key: bytes, backups_dir: Path) -> None:
    """SR-20: the target is built by the project's Alembic migrations, triggers and foreign keys included, not by create_all."""
    done = take_backup(engine, backup_key, backups_dir)
    restore(done.folder, target, engine.url, backup_key)

    with target_engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == done.manifest["alembic_revision"] == head_revision()
        triggers = set(connection.scalars(text("SELECT tgname FROM pg_trigger WHERE NOT tgisinternal")))
    assert TRIGGERS <= triggers
    assert "fk_ballot_chain_ballot_id_ballots" in {fk["name"] for fk in inspect(target_engine).get_foreign_keys("ballot_chain")}


# ---------------------------------------------------------------
# A real, committed election
# ---------------------------------------------------------------


class TestBackupAndRestore(CountedElection):
    """SR-20: backups of a real election: cast through the API, sealed, and audited."""

    def test_round_trip_restores_every_table_exactly(
        self, sealed, keys, engine: Engine, target: str, target_engine: Engine, backup_key: bytes, backups_dir: Path
    ) -> None:
        """SR-20: every row of every table comes back byte for byte: ciphertext, receipt hashes, the chain and the audit log."""
        done = take_backup(engine, backup_key, backups_dir)
        restored = restore(done.folder, target, engine.url, backup_key)

        for table in application_tables():
            assert table_rows(target_engine, table) == table_rows(engine, table), table.name
        assert done.manifest["ballot_count"] == 5 and done.manifest["label"] == "manual"
        assert restored.counts == {name: count for item in done.manifest["files"] for name, count in item["rows"].items()}
        assert restored.counts["ballot_chain"] == 5 and restored.counts["audit_log"] > 0
        with Session(target_engine) as session:
            receipts = session.scalars(text("SELECT receipt_hash FROM ballot_tokens WHERE consumed")).all()
            assert len(receipts) == 5 and all(re.fullmatch(r"[0-9a-f]{64}", receipt) for receipt in receipts)
            # SR-20: the restored copy passes the SR-13 and SR-16 checks the live database passes
            assert verify_chain(session, sealed["election_id"], keys[1], checkpoint_file(sealed["election_id"])) == []
            assert verify_audit_chain(session) == (restored.counts["audit_log"], None)
            # SR-20: the next serial id follows the restored ones
            top = session.scalar(select(func.max(AuditLogEntry.id)))
            assert session.scalar(text("SELECT nextval(pg_get_serial_sequence('audit_log', 'id'))")) == top + 1

    def test_each_file_holds_one_side_and_the_manifest_describes_them(
        self, sealed, engine: Engine, backup_key: bytes, backups_dir: Path
    ) -> None:
        """SR-20: identity tables in identity.jsonl.enc, ballot tables in ballot.jsonl.enc, and a manifest that matches."""
        done = take_backup(engine, backup_key, backups_dir, "before_open")
        manifest = json.loads((done.folder / MANIFEST).read_text(encoding="utf-8"))

        assert manifest == done.manifest
        assert set(manifest) == {"format", "backup_id", "created_at", "label", "alembic_revision", "files", "ballot_count"}
        assert (manifest["label"], manifest["alembic_revision"]) == ("before_open", head_revision())
        assert done.folder.name.endswith("_" + manifest["backup_id"])
        assert {line["table"] for line in decrypted(done.folder, manifest, backup_key, IDENTITY_FILE)} <= IDENTITY_TABLES
        assert {line["table"] for line in decrypted(done.folder, manifest, backup_key, BALLOT_FILE)} <= BALLOT_TABLES
        for item in manifest["files"]:
            assert hashlib.sha256((done.folder / item["name"]).read_bytes()).hexdigest() == item["sha256"]

    def test_backup_files_are_read_only_and_hold_no_plaintext(
        self, sealed, engine: Engine, backup_key: bytes, backups_dir: Path
    ) -> None:
        """SR-20: only the manifest and two ciphertext files are written, all read-only, and no row can be read from them."""
        done = take_backup(engine, backup_key, backups_dir)
        with engine.connect() as connection:
            receipts = list(connection.scalars(text("SELECT receipt_hash FROM ballot_tokens WHERE consumed")))
            payload = connection.scalar(text("SELECT encrypted_payload FROM ballots LIMIT 1"))
        plaintext = [b'"table"', b"Ortega", b"Whitfield", b"Northgate", str(sealed["election_id"]).encode(), payload[:24],
                     base64.b64encode(payload)[:24], *(receipt.encode() for receipt in receipts)]

        assert sorted(path.relative_to(done.folder).as_posix() for path in backups_dir.rglob("*") if path.is_file()) == sorted(
            [IDENTITY_FILE + ENCRYPTED, BALLOT_FILE + ENCRYPTED, MANIFEST]
        )
        for path in done.folder.iterdir():
            assert not os.access(path, os.W_OK), path.name
            with pytest.raises(PermissionError):
                path.write_bytes(b"")
            data = path.read_bytes()
            for text_found in plaintext:
                assert text_found not in data, (path.name, text_found)

    def test_a_backup_is_never_overwritten(
        self, sealed, engine: Engine, backup_key: bytes, backups_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SR-20: a second backup gets a new folder, and a folder that already exists is refused, never replaced."""
        first = take_backup(engine, backup_key, backups_dir)
        before = {path.name: path.read_bytes() for path in first.folder.iterdir()}
        second = take_backup(engine, backup_key, backups_dir)
        assert second.folder != first.folder and second.manifest["backup_id"] != first.manifest["backup_id"]

        # SR-20: the same time and the same id again: the folder exists, so the backup stops
        clash = first.manifest["backup_id"]
        made = dt.datetime.fromisoformat(first.manifest["created_at"])
        monkeypatch.setattr(backup_db.uuid, "uuid4", lambda: uuid.UUID(clash))
        monkeypatch.setattr(backup_db, "datetime", type("Fixed", (), {"now": staticmethod(lambda tz=None: made)}))
        with pytest.raises(BackupRefused) as refused:
            take_backup(engine, backup_key, backups_dir)

        assert refused.value.code == "backup_exists"
        assert {path.name: path.read_bytes() for path in first.folder.iterdir()} == before
        assert len(list(backups_dir.iterdir())) == 2

    @pytest.mark.parametrize(
        "tamper, code",
        [
            ("flipped byte", "manifest_mismatch"),
            ("flipped byte, manifest rehashed", "decrypt_failed"),
            ("files swapped", "manifest_mismatch"),
            ("files swapped, manifest rehashed", "decrypt_failed"),
            ("file from another backup", "manifest_mismatch"),
            ("file from another backup, manifest rehashed", "decrypt_failed"),
            ("manifest row count edited", "manifest_mismatch"),
            ("manifest ballot count edited", "manifest_mismatch"),
            ("manifest missing", "manifest_mismatch"),
            ("another backup key", "decrypt_failed"),
        ],
    )
    def test_a_tampered_backup_is_refused_and_the_target_left_empty(
        self, sealed, tamper: str, code: str, engine: Engine, target: str, target_engine: Engine,
        backup_key: bytes, backups_dir: Path, tmp_path: Path,
    ) -> None:
        """SR-20: any change to a backup is caught by the manifest's SHA-256 or by AES-GCM, before the target is touched."""
        done = take_backup(engine, backup_key, backups_dir)
        copy = writable_copy(done.folder, tmp_path / "copy")
        key = backup_key
        ballot_file, identity_file = BALLOT_FILE + ENCRYPTED, IDENTITY_FILE + ENCRYPTED
        if tamper.startswith("flipped byte"):
            data = bytearray((copy / ballot_file).read_bytes())
            data[len(data) // 2] ^= 0x01
            (copy / ballot_file).write_bytes(bytes(data))
        elif tamper.startswith("files swapped"):
            identity, ballots = (copy / identity_file).read_bytes(), (copy / ballot_file).read_bytes()
            (copy / identity_file).write_bytes(ballots)
            (copy / ballot_file).write_bytes(identity)
        elif tamper.startswith("file from another backup"):
            other = take_backup(engine, backup_key, backups_dir)
            (copy / ballot_file).write_bytes((other.folder / ballot_file).read_bytes())
        elif tamper == "manifest row count edited":
            edit_manifest(copy, lambda manifest: entry(manifest, ballot_file)["rows"].update(ballots=4))
        elif tamper == "manifest ballot count edited":
            edit_manifest(copy, lambda manifest: manifest.update(ballot_count=4))
        elif tamper == "manifest missing":
            (copy / MANIFEST).unlink()
        elif tamper == "another backup key":
            key = os.urandom(32)
        if tamper.endswith("manifest rehashed"):
            rehash(copy, ballot_file)
            rehash(copy, identity_file)

        assert refusal(copy, target, engine.url, key) == code
        assert target_is_empty(target_engine)

    def test_a_row_on_the_wrong_side_is_refused(
        self, sealed, engine: Engine, target: str, target_engine: Engine, backup_key: bytes, backups_dir: Path, tmp_path: Path
    ) -> None:
        """SR-20 (SR-12): even a file written with the key, with a matching manifest, may not carry an identity table on the ballot side."""
        done = take_backup(engine, backup_key, backups_dir)
        copy = writable_copy(done.folder, tmp_path / "copy")
        backup_id, ballot_file = done.manifest["backup_id"], BALLOT_FILE + ENCRYPTED
        moved = decrypted(copy, done.manifest, backup_key, IDENTITY_FILE)[0]
        ballots = decrypt_payload(backup_key, backup_id, BALLOT_FILE, (copy / ballot_file).read_bytes())
        (copy / ballot_file).write_bytes(encrypt_payload(backup_key, backup_id, BALLOT_FILE, ballots + (json.dumps(moved) + "\n").encode("utf-8")))
        edit_manifest(copy, lambda manifest: entry(manifest, ballot_file)["rows"].update({moved["table"]: 1}))
        rehash(copy, ballot_file)

        with pytest.raises(BackupRefused) as refused:
            restore(copy, target, engine.url, backup_key)

        assert refused.value.code == "manifest_mismatch" and "holds a table from the other side" in str(refused.value)
        assert target_is_empty(target_engine)

    def test_a_failed_restore_rolls_everything_back(
        self, sealed, engine: Engine, target: str, target_engine: Engine, backup_key: bytes, backups_dir: Path, tmp_path: Path
    ) -> None:
        """SR-20: a manifest revision before the audit log's version column: the inserts fail and the migrations are undone too."""
        done = take_backup(engine, backup_key, backups_dir)
        copy = writable_copy(done.folder, tmp_path / "copy")
        script = ScriptDirectory.from_config(Config(str(BACKEND_DIR / "alembic.ini")))
        # VULN-05, VULN-06: head is no longer the revision that added audit_log.version (0014), so
        # the revision before that one is named, not the one before head
        older = script.get_revision("0014").down_revision
        edit_manifest(copy, lambda manifest: manifest.update(alembic_revision=older))

        assert refusal(copy, target, engine.url, backup_key) == "restore_failed"
        assert target_is_empty(target_engine)

    def test_restore_script_prints_pass_with_the_counts(self, sealed, scripts_on_test_db, backups_dir: Path, capsys) -> None:
        """SR-20: python -m scripts.backup_db then python -m scripts.restore_db --backup <folder>."""
        assert backup_db.main(["--label", "close"]) == 0
        folder = next(backups_dir.iterdir())
        assert f"written to {folder}" in capsys.readouterr().out

        assert restore_db.main(["--backup", str(folder)]) == 0
        output = capsys.readouterr().out
        assert "PASS: backup" in output and "5 ballots" in output and "  ballot_chain: 5" in output


class TestRecoveryTest(CountedElection):
    """SR-20: the recovery test: a timed restore, zero loss and reconciliation, on a real election."""

    def tampered_report(self, engine: Engine, target: str, target_engine: Engine, backup_key: bytes, backups_dir: Path, *tamper: str):
        """SR-20: backup and restore, then a change to the restored copy only, then the checks."""
        done = take_backup(engine, backup_key, backups_dir, "recovery_test")
        started = time.monotonic()
        restore(done.folder, target, engine.url, backup_key)
        with target_engine.begin() as connection:
            for statement in tamper:
                connection.execute(text(statement))
        return run_checks(target_engine, done.manifest, recovery_test.live_public_key(), started, 1800)

    def test_recovery_test_passes_on_clean_data(self, sealed, scripts_on_test_db, engine: Engine, backups_dir: Path, capsys) -> None:
        """SR-20: python -m scripts.recovery_test --reset-target: all three checks pass, exit 0, and no audit event is written."""
        with engine.connect() as connection:
            audit_before = connection.scalar(text("SELECT count(*) FROM audit_log"))

        assert recovery_test.main(["--reset-target"]) == 0
        output = capsys.readouterr().out

        for check in ("time", "zero_loss", "reconciliation"):
            assert f"  {check}: PASS" in output
        assert "5 ballots restored of 5; 1 chain(s) verified" in output
        assert re.search(r"Total time, backup included: \d+\.\d\d s", output)
        assert output.rstrip().endswith("PASS: all checks passed")
        (folder,) = backups_dir.iterdir()
        assert json.loads((folder / MANIFEST).read_text(encoding="utf-8"))["label"] == "recovery_test"
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM audit_log")) == audit_before

    def test_zero_loss_fails_when_a_ballot_is_missing(
        self, sealed, engine: Engine, target: str, target_engine: Engine, backup_key: bytes, backups_dir: Path
    ) -> None:
        """SR-20: a chained ballot removed from the restored copy (its trigger and foreign key off there only) fails zero_loss."""
        report = self.tampered_report(
            engine, target, target_engine, backup_key, backups_dir,
            "ALTER TABLE ballot_chain DROP CONSTRAINT fk_ballot_chain_ballot_id_ballots",
            "ALTER TABLE ballots DISABLE TRIGGER ballots_append_only",
            "DELETE FROM ballots WHERE id = (SELECT ballot_id FROM ballot_chain ORDER BY position LIMIT 1)",
            "ALTER TABLE ballots ENABLE TRIGGER ballots_append_only",
        )
        checks = {check.name: check for check in report.checks}

        assert not report.passed and not checks["zero_loss"].passed
        assert "missing_ballot" in checks["zero_loss"].detail
        assert "4 ballots restored, the backup holds 5" in checks["zero_loss"].detail
        assert checks["time"].passed
        # the live database still holds every ballot
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM ballots")) == 5

    def test_reconciliation_fails_when_a_receipt_hash_is_cleared(
        self, sealed, engine: Engine, target: str, target_engine: Engine, backup_key: bytes, backups_dir: Path
    ) -> None:
        """SR-20: a used token without its receipt hash could no longer confirm a voter's reference: reconciliation fails."""
        report = self.tampered_report(
            engine, target, target_engine, backup_key, backups_dir,
            "UPDATE ballot_tokens SET receipt_hash = NULL WHERE id = (SELECT id FROM ballot_tokens WHERE consumed ORDER BY id LIMIT 1)",
        )
        checks = {check.name: check for check in report.checks}

        assert not report.passed and not checks["reconciliation"].passed and checks["zero_loss"].passed
        assert "1 used token(s) without a receipt hash" in checks["reconciliation"].detail

    def test_reconciliation_fails_when_the_totals_differ(
        self, sealed, engine: Engine, target: str, target_engine: Engine, backup_key: bytes, backups_dir: Path
    ) -> None:
        """SR-20: an elector no longer marked voted makes the per-election totals disagree."""
        report = self.tampered_report(
            engine, target, target_engine, backup_key, backups_dir,
            "UPDATE voter_participation SET state = 'issued' WHERE (roll_id, election_id) = "
            "(SELECT roll_id, election_id FROM voter_participation WHERE state = 'voted' ORDER BY roll_id LIMIT 1)",
        )
        checks = {check.name: check for check in report.checks}

        assert not checks["reconciliation"].passed
        assert "5 used tokens, 5 ballots, 4 voted" in checks["reconciliation"].detail

    def test_time_fails_over_the_limit(self, sealed, scripts_on_test_db, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        """SR-20: a restore and checks slower than RESTORE_TIME_LIMIT_SECONDS fail the test, even with no data lost."""
        monkeypatch.setattr(settings, "restore_time_limit_seconds", 1e-9)

        assert recovery_test.main(["--reset-target"]) == 1
        output = capsys.readouterr().out

        assert "  time: FAIL" in output and "  zero_loss: PASS" in output and "  reconciliation: PASS" in output
        assert output.rstrip().endswith("FAIL: at least one check failed")


def test_recovery_checks_never_join_identity_and_ballot_tables() -> None:
    """SR-20 (SR-12): each query of the checks reads one side only; totals are compared in Python, per election."""
    source = (BACKEND_DIR / "scripts" / "recovery_test.py").read_text(encoding="utf-8")
    queries = re.findall(r'"(SELECT [^"]*)"', source)

    assert len(queries) >= 5
    for query in queries:
        named = set(re.findall(r"\b[a-z_]+\b", query))
        assert not (named & IDENTITY_TABLES and named & BALLOT_TABLES), query
