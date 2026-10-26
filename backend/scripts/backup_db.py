"""
SR-20: an encrypted, tamper-evident backup of the whole database. Run inside backend/:

    python -m scripts.backup_db --label before_open    # before polls open
    python -m scripts.backup_db --label close          # at the close of polls
    python -m scripts.backup_db                         # on demand (label manual)

Every application table is read in ONE read-only REPEATABLE READ transaction, so the identity file
and the ballot file come from the same moment. Each SR-12 side goes to its own file
(identity.jsonl.enc, ballot.jsonl.enc), encrypted with AES-256-GCM under the backup key
(scripts/gen_backup_key.py), never the SR-11 ballot key. The ballots inside stay SR-11 encrypted
as well. manifest.json records the backup id, time, label, Alembic revision, each file's SHA-256
and row counts, and the ballot count.

Each backup gets a new folder, BACKUPS_DIR/<UTC time>_<backup id>/, made read-only. A backup is
never overwritten or deleted, and no plaintext is ever written to disk.
"""

import argparse
import hashlib
import json
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Engine, text

from app.config import settings
from app.db import engine
# SR-20: SR-17's read-only REPEATABLE READ snapshot, reused: a backup can neither write nor see half a change
from app.house_count import read_only_snapshot
from app.stores import IDENTITY_TABLES
from scripts.backup_common import (
    BALLOT_FILE,
    ENCRYPTED,
    IDENTITY_FILE,
    LABELS,
    MANIFEST,
    BackupRefused,
    application_tables,
    encrypt_payload,
    load_backup_key,
    make_read_only,
    payload,
    read_rows,
)


@dataclass(frozen=True)
class Backup:
    folder: Path
    manifest: dict


def take_backup(db_engine: Engine, key: bytes, backups_dir: Path, label: str = "manual") -> Backup:
    """SR-20: one backup into a new folder. Raises BackupRefused before writing anything if it cannot."""
    if label not in LABELS:
        raise BackupRefused("bad_label", f"the label must be one of: {', '.join(LABELS)}")
    tables = application_tables()
    with read_only_snapshot(db_engine) as session:
        revision = session.scalar(text("SELECT version_num FROM alembic_version"))
        rows = {table.name: read_rows(session, table) for table in tables}
    if not revision:
        raise BackupRefused("no_revision", "the database has no Alembic revision; run alembic upgrade head first")

    backup_id = str(uuid.uuid4())
    created_at = datetime.now(UTC)
    sides = {
        IDENTITY_FILE: [t for t in tables if t.name in IDENTITY_TABLES],
        BALLOT_FILE: [t for t in tables if t.name not in IDENTITY_TABLES],
    }
    # SR-20: encrypted in memory; only ciphertext reaches the disk
    encrypted = {name: encrypt_payload(key, backup_id, name, payload(side, rows)) for name, side in sides.items()}

    folder = backups_dir / f"{created_at:%Y%m%dT%H%M%SZ}_{backup_id}"
    backups_dir.mkdir(parents=True, exist_ok=True)
    try:
        folder.mkdir(exist_ok=False)  # SR-20: always a new folder, never an existing backup
    except FileExistsError:
        raise BackupRefused("backup_exists", f"{folder} already exists; a backup is never overwritten") from None
    manifest = {
        "format": 1,
        "backup_id": backup_id,
        "created_at": created_at.isoformat(),
        "label": label,
        "alembic_revision": revision,
        "files": [
            {
                "name": name + ENCRYPTED,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "rows": {table.name: len(rows[table.name]) for table in sides[name]},
            }
            for name, blob in encrypted.items()
        ],
        # VULN-01: every accepted ballot, sealed (ballots) or still held for its seal (pending_ballots)
        "ballot_count": len(rows["ballots"]) + len(rows["pending_ballots"]),
    }
    for name, blob in encrypted.items():
        (folder / (name + ENCRYPTED)).write_bytes(blob)
    (folder / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    for path in folder.iterdir():
        make_read_only(path)
    return Backup(folder, manifest)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-20: take an encrypted backup of the database")
    parser.add_argument("--label", choices=LABELS[:3], default="manual", help="before_open, close or manual (default)")
    args = parser.parse_args(argv)
    print("SR-20 database backup")
    try:
        key = load_backup_key(settings.backend_path(settings.backup_key_file))
        done = take_backup(engine, key, settings.backend_path(settings.backups_dir), args.label)
    except BackupRefused as refused:
        print(f"REFUSED: {refused}")
        return 1
    print(f"Backup {done.manifest['backup_id']} ({done.manifest['label']}) written to {done.folder}")
    print(f"Alembic revision: {done.manifest['alembic_revision']}. Ballots: {done.manifest['ballot_count']}")
    for entry in done.manifest["files"]:
        print(f"  {entry['name']}: {sum(entry['rows'].values())} rows in {len(entry['rows'])} tables, SHA-256 {entry['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
