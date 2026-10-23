"""
SR-11: the pre-release storage audit. Run inside backend/, against the release database:

    python -m scripts.audit_ballots

Prints one line per check (PASS, FAIL or SKIPPED) and a summary, and exits with code 1 if any
check fails, 0 otherwise. It never prints a decrypted ballot, a ciphertext or the key: only
ballot ids, table and column names, file names and reasons.
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.ballot_crypto import (
    FORMAT_VERSION,
    MIN_BLOB_BYTES,
    PAYLOAD_FIELDS,
    BallotDecryptionError,
    BallotKeyError,
    decrypt_ballot,
    load_key,
)
from app.config import PROJECT_DIR, settings
from app.db import SessionLocal
from app.stores import ballot_rows

# SR-11: the only columns ballots may have. Any other column could hold a readable ballot.
BALLOT_COLUMNS = {"id", "election_id", "encrypted_payload"}
LEGACY_BALLOT_COLUMNS = {"division_id", "ciphertext", "nonce", "key_id"}
# SR-11: the other tables that touch ballots (receipts, participation, the audit log), with the
# columns they may have. A new column there has to be reviewed before a release.
OTHER_TABLES = {
    # SR-12: tokens no longer hold expires_at or consumed_at
    "ballot_tokens": {"id", "election_id", "token_hash", "receipt_reference"},
    "voter_participation": {"roll_id", "election_id", "state"},
    # SR-13: the hash chain holds ids and hashes of the ciphertext, never ballot content
    "ballot_chain": {"election_id", "position", "batch_no", "ballot_id", "prev_hash", "entry_hash"},
    "audit_log": {"id", "created_at", "event_type", "actor", "details", "prev_hash", "hash"},
}
SKIP_DIRS = {".git", "node_modules", ".venv", "dist", "__pycache__", ".pytest_cache"}

Status = Literal["PASS", "FAIL", "SKIPPED"]


@dataclass
class Check:
    name: str
    status: Status
    reason: str


def columns_of(db: Session, table: str) -> dict[str, str]:
    rows = db.execute(
        text(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = :table"
        ),
        {"table": table},
    )
    return {name: data_type for name, data_type in rows}


def readable_reason(blob: bytes) -> str | None:
    """SR-11: why stored bytes look like a readable ballot, or None. A plain text scan, nothing clever."""
    try:
        json.loads(blob.decode("utf-8"))
        return "readable JSON"
    except (UnicodeDecodeError, ValueError):
        pass
    if any(field.encode() in blob for field in PAYLOAD_FIELDS):
        return "contains ballot field names"
    return None


def check_ballot_records(db: Session) -> Check:
    """SR-11 (a): every ballot row is version 1, long enough, and decrypts with its own ballot and election id."""
    name = "a. ballot records"
    if "encrypted_payload" not in columns_of(db, "ballots"):
        return Check(name, "FAIL", "ballots has no encrypted_payload column (run alembic upgrade head)")
    # SR-12: in ballot id order, so the failing ids it prints do not show the order ballots arrived in
    rows = list(ballot_rows(db))
    problems: list[str] = []
    for ballot_id, election_id, stored in rows:
        blob = bytes(stored)
        reason = readable_reason(blob)
        if reason is None and len(blob) < MIN_BLOB_BYTES:
            reason = "too short to be encrypted"
        elif reason is None and blob[0] != FORMAT_VERSION:
            reason = "unknown format version"  # SR-11: never the byte itself, which could be ballot text
        elif reason is None:
            try:
                decrypt_ballot(blob, ballot_id, election_id)  # in memory only; the result is never shown
            except BallotKeyError:
                return Check(name, "FAIL", f"{len(rows)} ballot(s) cannot be checked: the ballot key is unusable (see d)")
            except BallotDecryptionError:
                reason = "does not decrypt with its own ballot and election id"
        if reason is not None:
            problems.append(f"{ballot_id} ({reason})")
    if problems:
        return Check(name, "FAIL", f"{len(problems)} of {len(rows)} plaintext or invalid: " + "; ".join(problems))
    return Check(name, "PASS", f"{len(rows)} ballot(s), all version 1 and each decrypts with its own ballot and election id")


def check_ballot_columns(db: Session) -> Check:
    """SR-11 (b): the old plaintext columns are gone, and ballots has nothing but id, election and the ciphertext."""
    name = "b. ballots columns"
    columns = columns_of(db, "ballots")
    unexpected = sorted(set(columns) - BALLOT_COLUMNS)
    if unexpected:
        legacy = sorted(set(unexpected) & LEGACY_BALLOT_COLUMNS)
        detail = f" (old plaintext columns: {', '.join(legacy)})" if legacy else ""
        return Check(name, "FAIL", f"unexpected column(s) {', '.join(unexpected)}{detail}")
    if columns.get("encrypted_payload") != "bytea":
        return Check(name, "FAIL", "encrypted_payload is missing or is not bytea")
    return Check(name, "PASS", "only id, election_id and encrypted_payload (bytea); no plaintext ballot columns")


def check_other_tables(db: Session) -> Check:
    """SR-11 (c): receipts, participation and the audit log have no column that could hold ballot content."""
    name = "c. other tables"
    found = [f"{table}.{column}" for table, allowed in OTHER_TABLES.items() for column in sorted(set(columns_of(db, table)) - allowed)]
    if found:
        return Check(name, "FAIL", f"unreviewed column(s) that could hold ballot content: {', '.join(found)}")
    return Check(name, "PASS", f"{', '.join(OTHER_TABLES)} hold no ballot content columns")


def check_key_file(path: Path) -> Check:
    """SR-11 (d): the key exists and is exactly 32 bytes (and owner-only on POSIX)."""
    name = "d. key file"
    try:
        load_key(path)
    except BallotKeyError as problem:
        return Check(name, "FAIL", str(problem))
    permissions = "owner-only" if os.name == "posix" else "permission check skipped on Windows"
    return Check(name, "PASS", f"{path} is 32 bytes ({permissions})")


def check_key_in_git(path: Path) -> Check:
    """SR-11 (d): the key is ignored by git and not tracked. Without git this is SKIPPED, never PASS."""
    name = "d. key not in git"
    folder = path.parent if path.parent.is_dir() else PROJECT_DIR
    try:
        ignored = subprocess.run(["git", "check-ignore", "-q", "--", str(path)], cwd=folder, capture_output=True)
        tracked = subprocess.run(["git", "ls-files", "--error-unmatch", "--", str(path)], cwd=folder, capture_output=True)
    except FileNotFoundError:
        return Check(name, "SKIPPED", "git is not available, so it is not confirmed that the key is ignored and untracked")
    if ignored.returncode == 128:
        return Check(name, "SKIPPED", "the key is not inside a git repository, so git could not check it")
    if tracked.returncode == 0:
        return Check(name, "FAIL", f"{path} is tracked by git: remove it from the repository and rotate the key")
    if ignored.returncode != 0:
        return Check(name, "FAIL", f"{path} is not ignored by git: add keys/ to .gitignore")
    return Check(name, "PASS", "ignored by git (git check-ignore) and not tracked (git ls-files)")


def check_logs(db: Session, project_dir: Path) -> Check:
    """SR-11 (e): the audit log and any log files name none of the encrypted payload's fields."""
    name = "e. audit log and log files"
    hits = [
        f"audit_log id {entry_id}"
        for entry_id, line in db.execute(text("SELECT id, event_type || ' ' || actor || ' ' || details::text FROM audit_log"))
        if any(field in line for field in PAYLOAD_FIELDS)
    ]
    entries = db.scalar(text("SELECT count(*) FROM audit_log"))
    log_files = []
    for folder, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        log_files += [Path(folder) / f for f in files if f.endswith(".log")]
    for log_file in log_files:
        if any(field in log_file.read_text(encoding="utf-8", errors="ignore") for field in PAYLOAD_FIELDS):
            hits.append(str(log_file))
    if hits:
        return Check(name, "FAIL", f"ballot field names found in: {', '.join(hits)}")
    return Check(name, "PASS", f"{entries} audit entries and {len(log_files)} log file(s) scanned; no ballot field names")


def run_audit(db: Session, project_dir: Path) -> list[Check]:
    """SR-11: every check, in order. The key is the one the API uses (BALLOT_KEY_FILE)."""
    key = settings.ballot_key_file
    return [
        check_ballot_records(db),
        check_ballot_columns(db),
        check_other_tables(db),
        check_key_file(key),
        check_key_in_git(key),
        check_logs(db, project_dir),
    ]


def main() -> int:
    print("SR-11 pre-release ballot storage audit")
    with SessionLocal() as db:
        checks = run_audit(db, PROJECT_DIR)
    for check in checks:
        print(f"{check.status:<8} {check.name}: {check.reason}")
    failed = sum(check.status == "FAIL" for check in checks)
    skipped = sum(check.status == "SKIPPED" for check in checks)
    passed = len(checks) - failed - skipped
    print(f"Summary: {passed} passed, {failed} failed, {skipped} skipped")
    if skipped:
        print("WARNING: a skipped check was not verified. Run the audit where git is available, inside the repository.")
    print("Result: FAIL (exit code 1)" if failed else "Result: PASS (exit code 0)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
