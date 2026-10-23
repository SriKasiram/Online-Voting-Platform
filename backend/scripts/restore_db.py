"""
SR-20: restores a backup into a separate, empty database. Run inside backend/:

    python -m scripts.restore_db --backup backups/<UTC time>_<backup id>

The target is RESTORE_DATABASE_URL. It is refused if it is unset, if it is the live database, or if
it already holds any table: a restore never overwrites data. Then, in order:
  1. each encrypted file's SHA-256 must match the manifest (manifest_mismatch), and must decrypt
     with the backup key, bound to this backup id and file name (decrypt_failed);
  2. the rows of each table must be on that file's SR-12 side and their counts must match the
     manifest (manifest_mismatch);
  3. in ONE transaction: the project's Alembic migrations run on the target up to the manifest's
     revision (so every constraint and the SR-13 and SR-16 append-only triggers exist), every row
     is inserted in foreign-key order, and serial sequences are moved past the restored ids.
     Anything that fails rolls all of it back, schema included.
Prints PASS with the counts, or REFUSED with the reason. No pg_dump, psql or pg_restore.
"""

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError

from app.config import BACKEND_DIR, settings
from app.stores import BALLOT_TABLES, IDENTITY_TABLES
from scripts.backup_common import (
    BALLOT_FILE,
    ENCRYPTED,
    IDENTITY_FILE,
    MANIFEST,
    BackupRefused,
    application_tables,
    check_target,
    decode_value,
    decrypt_payload,
    hidden,
    load_backup_key,
    target_is_empty,
)

SIDES = {IDENTITY_FILE: IDENTITY_TABLES, BALLOT_FILE: BALLOT_TABLES}


@dataclass(frozen=True)
class Restored:
    manifest: dict
    counts: dict[str, int]


def read_manifest(folder: Path) -> dict:
    """SR-20: the manifest, shaped as backup_db writes it, or manifest_mismatch."""
    try:
        manifest = json.loads((folder / MANIFEST).read_text(encoding="utf-8"))
        names = sorted(entry["name"] for entry in manifest["files"])
        well_formed = (
            names == sorted(name + ENCRYPTED for name in SIDES)
            and isinstance(manifest["backup_id"], str)
            and isinstance(manifest["alembic_revision"], str)
            and type(manifest["ballot_count"]) is int
            and all(isinstance(entry["sha256"], str) and isinstance(entry["rows"], dict) for entry in manifest["files"])
        )
    except (OSError, ValueError, KeyError, TypeError):
        well_formed = False
    if not well_formed:
        raise BackupRefused("manifest_mismatch", f"{folder / MANIFEST} is missing or not a backup manifest")
    return manifest


def decrypted_rows(folder: Path, manifest: dict, key: bytes) -> dict[str, list[dict[str, Any]]]:
    """SR-20: every file checked, decrypted and counted, before anything touches the target."""
    rows: dict[str, list[dict[str, Any]]] = {}
    for entry in manifest["files"]:
        name = entry["name"].removesuffix(ENCRYPTED)
        try:
            blob = (folder / entry["name"]).read_bytes()
        except OSError:
            raise BackupRefused("manifest_mismatch", f"{entry['name']} is missing") from None
        if hashlib.sha256(blob).hexdigest() != entry["sha256"]:
            raise BackupRefused("manifest_mismatch", f"{entry['name']} does not have the SHA-256 the manifest records")
        data = decrypt_payload(key, manifest["backup_id"], name, blob)
        found: dict[str, list[dict[str, Any]]] = {}
        for number, line in enumerate(data.decode("utf-8").splitlines(), start=1):
            record = json.loads(line)
            if record["table"] not in SIDES[name]:
                raise BackupRefused("manifest_mismatch", f"{entry['name']} line {number} holds a table from the other side")
            found.setdefault(record["table"], []).append(record["row"])
        counts = {table: len(found.get(table, [])) for table in set(found) | set(entry["rows"])}
        if counts != {table: entry["rows"].get(table, 0) for table in counts}:
            raise BackupRefused("manifest_mismatch", f"{entry['name']} does not hold the row counts the manifest records")
        rows |= found
    if len(rows.get("ballots", [])) != manifest["ballot_count"]:
        raise BackupRefused("manifest_mismatch", "the ballots do not match the manifest's ballot_count")
    return rows


def migrate(connection: Any, revision: str) -> None:
    """SR-20: the project's own migrations, run on the target's connection, so the schema is exactly the backup's."""
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.attributes["connection"] = connection
    command.upgrade(config, revision)


def reset_sequences(connection: Any) -> None:
    """SR-20: serial ids continue after the restored ones, so the next audit entry gets a new id."""
    for table in application_tables():
        for column in table.primary_key.columns:
            sequence = connection.scalar(text("SELECT pg_get_serial_sequence(:t, :c)"), {"t": table.name, "c": column.name})
            if sequence:
                connection.execute(
                    text(f'SELECT setval(:s, COALESCE((SELECT MAX("{column.name}") FROM "{table.name}"), 1), '
                         f'(SELECT MAX("{column.name}") FROM "{table.name}") IS NOT NULL)'),
                    {"s": sequence},
                )


def restore(folder: Path, target_url: str, live_url: URL | str, key: bytes) -> Restored:
    """SR-20: the whole restore, or BackupRefused with the target left as it was."""
    target = check_target(target_url, live_url)
    manifest = read_manifest(folder)
    rows = decrypted_rows(folder, manifest, key)
    engine: Engine = create_engine(target, hide_parameters=True)
    try:
        try:
            empty = target_is_empty(engine)
        except SQLAlchemyError as problem:
            raise BackupRefused("target_unreachable", f"could not connect to {hidden(target)} ({type(problem).__name__})") from None
        if not empty:
            raise BackupRefused("target_not_empty", f"{hidden(target)} already holds tables; a restore never overwrites data")
        try:
            with engine.begin() as connection:
                migrate(connection, manifest["alembic_revision"])
                for table in application_tables():
                    decoded = [{name: decode_value(table.c[name], value) for name, value in row.items()} for row in rows.get(table.name, [])]
                    if decoded:
                        connection.execute(table.insert(), decoded)
                reset_sequences(connection)
        except (SQLAlchemyError, ValueError, KeyError, TypeError) as problem:
            # SR-20: the type only: a database message could repeat a row of the backup
            raise BackupRefused("restore_failed", f"the restore was rolled back ({type(problem).__name__})") from None
    finally:
        engine.dispose()
    # SR-20: the manifest's counts, which decrypted_rows proved the files hold, empty tables included
    return Restored(manifest, {table: count for entry in manifest["files"] for table, count in entry["rows"].items()})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-20: restore a backup into the separate restore database")
    parser.add_argument("--backup", type=Path, required=True, help="the backup folder")
    args = parser.parse_args(argv)
    print("SR-20 database restore")
    try:
        key = load_backup_key(settings.backend_path(settings.backup_key_file))
        done = restore(args.backup, settings.restore_database_url.get_secret_value(), settings.database_url(), key)
    except BackupRefused as refused:
        print(f"REFUSED: {refused}")
        return 1
    total = sum(done.counts.values())
    print(f"PASS: backup {done.manifest['backup_id']} restored at revision {done.manifest['alembic_revision']}: "
          f"{total} rows in {len(done.counts)} tables, {done.manifest['ballot_count']} ballots")
    for table, count in sorted(done.counts.items()):
        print(f"  {table}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
