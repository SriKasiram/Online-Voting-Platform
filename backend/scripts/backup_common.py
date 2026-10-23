"""
SR-20: what the backup, restore and recovery-test scripts share: the backup key, the lossless row
encoding, the AES-256-GCM file format, the manifest, and the checks that keep a restore away from
the live database.

File format (identity.jsonl.enc, ballot.jsonl.enc): version byte 0x01, a 12-byte random nonce, then
the AES-256-GCM ciphertext and tag of a JSON Lines payload. The associated data is
b"evoting-backup-v1|" + backup id + b"|" + payload name, so a file decrypts only in its own backup
and under its own name: swapped or borrowed files fail. Plaintext never touches the disk.

Everything here runs in Python through SQLAlchemy: no pg_dump, psql or pg_restore.
"""

import base64
import datetime as dt
import decimal
import enum
import json
import os
import stat
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import JSON, Date, DateTime, Engine, Enum, Float, LargeBinary, Numeric, Table, Uuid, create_engine, inspect, select, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

import app.models  # noqa: F401  (registers every table on Base.metadata)
from app.db import Base
from app.stores import BALLOT_TABLES, IDENTITY_TABLES, NOT_APPLICATION_DATA

FORMAT_VERSION = 0x01
NONCE_BYTES = 12
KEY_BYTES = 32
AAD_TAG = b"evoting-backup-v1|"
IDENTITY_FILE = "identity.jsonl"
BALLOT_FILE = "ballot.jsonl"
ENCRYPTED = ".enc"
MANIFEST = "manifest.json"
LABELS = ("before_open", "close", "manual", "recovery_test")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", ""}


class BackupRefused(Exception):
    """SR-20: the backup or restore stopped. `code` says why; the message says what to do."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


# ---------------------------------------------------------------
# The key
# ---------------------------------------------------------------


def load_backup_key(path: Path) -> bytes:
    """SR-20: the 32-byte backup key, or BackupRefused. On POSIX it must not be readable by others."""
    path = Path(path)
    if not path.is_file():
        raise BackupRefused("backup_key_missing", f"no backup key at {path}. Create it with: python -m scripts.gen_backup_key")
    key = path.read_bytes()
    if len(key) != KEY_BYTES:
        raise BackupRefused("backup_key_invalid", f"{path} must be exactly {KEY_BYTES} bytes (AES-256)")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise BackupRefused("backup_key_invalid", f"{path} can be read by other users: chmod 600 it")
    return key


# ---------------------------------------------------------------
# Tables and rows
# ---------------------------------------------------------------


def application_tables() -> list[Table]:
    """SR-20: every table of the models, in foreign-key order, each on exactly one SR-12 side."""
    tables = [table for table in Base.metadata.sorted_tables if table.name not in NOT_APPLICATION_DATA]
    unsided = sorted(table.name for table in tables if table.name not in IDENTITY_TABLES | BALLOT_TABLES)
    if unsided:
        raise BackupRefused("table_without_side", f"table(s) on neither SR-12 side: {', '.join(unsided)}")
    return tables


def encode_value(value: Any) -> Any:
    """SR-20: a database value as JSON, without loss. Tagged where JSON has no type of its own."""
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray | memoryview):
        return {"$b64": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dt.datetime):
        return {"$datetime": value.isoformat()}
    if isinstance(value, dt.date):
        return {"$date": value.isoformat()}
    if isinstance(value, decimal.Decimal):
        return {"$decimal": str(value)}
    if isinstance(value, dict | list):
        return value
    raise TypeError(f"no backup encoding for {type(value).__name__}")


def _tagged(value: Any, tag: str) -> Any:
    if not isinstance(value, dict) or set(value) != {tag}:
        raise ValueError(f"expected a {tag} value")
    return value[tag]


def decode_value(column: Any, value: Any) -> Any:
    """SR-20: the reverse of encode_value, led by the column's own type, so JSON values stay as they were."""
    if value is None:
        return None
    kind = column.type
    if isinstance(kind, JSON):
        return value
    if isinstance(kind, LargeBinary):
        return base64.b64decode(_tagged(value, "$b64"), validate=True)
    if isinstance(kind, Uuid):
        return uuid.UUID(value)
    if isinstance(kind, DateTime):
        return dt.datetime.fromisoformat(_tagged(value, "$datetime"))
    if isinstance(kind, Date):
        return dt.date.fromisoformat(_tagged(value, "$date"))
    if isinstance(kind, Float):
        return value
    if isinstance(kind, Numeric):
        return decimal.Decimal(_tagged(value, "$decimal"))
    if isinstance(kind, Enum) and kind.enum_class is not None:
        return kind.enum_class(value)
    return value


def read_rows(db: Session, table: Table) -> list[dict[str, Any]]:
    """SR-20: every row, encoded, in primary-key order, so the same data always gives the same file."""
    rows = db.execute(select(table).order_by(*table.primary_key.columns))
    return [{column.name: encode_value(row._mapping[column]) for column in table.columns} for row in rows]


def payload(tables: Iterable[Table], rows: dict[str, list[dict[str, Any]]]) -> bytes:
    """SR-20: one JSON Lines payload: {"table": name, "row": {...}} per row, table by table."""
    lines = [
        json.dumps({"table": table.name, "row": row}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        for table in tables
        for row in rows[table.name]
    ]
    return ("\n".join(lines) + "\n" if lines else "").encode("utf-8")


# ---------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------


def associated_data(backup_id: str, name: str) -> bytes:
    # SR-20: binds a file to its backup and its name, so it cannot be swapped, renamed or reused
    return AAD_TAG + backup_id.encode("ascii") + b"|" + name.encode("ascii")


def encrypt_payload(key: bytes, backup_id: str, name: str, data: bytes) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return bytes([FORMAT_VERSION]) + nonce + AESGCM(key).encrypt(nonce, data, associated_data(backup_id, name))


def decrypt_payload(key: bytes, backup_id: str, name: str, blob: bytes) -> bytes:
    """SR-20: the payload, or BackupRefused("decrypt_failed"): wrong key, altered bytes, or another backup's file."""
    if len(blob) < 1 + NONCE_BYTES + 16 or blob[0] != FORMAT_VERSION:
        raise BackupRefused("decrypt_failed", f"{name}{ENCRYPTED} is not a version 1 backup file")
    try:
        return AESGCM(key).decrypt(blob[1 : 1 + NONCE_BYTES], blob[1 + NONCE_BYTES :], associated_data(backup_id, name))
    except InvalidTag:
        raise BackupRefused("decrypt_failed", f"{name}{ENCRYPTED} did not decrypt: wrong key, altered, or from another backup") from None


def make_read_only(path: Path) -> None:
    # SR-20: a backup must not be edited by accident; on Windows this sets the read-only attribute
    os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


# ---------------------------------------------------------------
# Where a restore may go
# ---------------------------------------------------------------


def _place(url: URL) -> tuple[str, int, str | None]:
    host = (url.host or "").lower()
    return ("local" if host in LOCAL_HOSTS else host, url.port or 5432, url.database)


def check_target(target_url: str, live_url: URL | str) -> URL:
    """SR-20: the restore target, parsed, or BackupRefused if it is unset or is the live database."""
    if not target_url:
        raise BackupRefused("no_restore_database", "RESTORE_DATABASE_URL is not set: give the URL of a separate database")
    try:
        target = make_url(target_url)
    except Exception:
        raise BackupRefused("no_restore_database", "RESTORE_DATABASE_URL is not a database URL") from None
    if _place(target) == _place(make_url(live_url) if isinstance(live_url, str) else live_url):
        raise BackupRefused("target_is_live", "RESTORE_DATABASE_URL points at the live database; a restore never goes there")
    return target


def target_is_empty(engine: Engine) -> bool:
    """SR-20: no table at all (application or alembic_version) in the target's public schema."""
    return not inspect(engine).get_table_names(schema="public")


def reset_target(target_url: str, live_url: URL | str) -> None:
    """
    SR-20: empties the target by dropping and recreating its public schema. Only for a database
    that is not the live one AND whose name ends with "_restore", so a typo can never empty
    anything that matters.
    """
    target = check_target(target_url, live_url)
    if not (target.database or "").endswith("_restore"):
        raise BackupRefused("reset_refused", f"only a database whose name ends with _restore is reset (got {target.database!r})")
    engine = create_engine(target, hide_parameters=True)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    except SQLAlchemyError as problem:
        # SR-20: the error type only, and the URL without its password
        raise BackupRefused(
            "reset_failed", f"could not empty {hidden(target)} ({type(problem).__name__}); the database user must own it"
        ) from None
    finally:
        engine.dispose()


def hidden(url: URL) -> str:
    return url.render_as_string(hide_password=True)
