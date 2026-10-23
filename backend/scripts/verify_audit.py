"""
SR-16: verifies the whole audit log and its signed checkpoints. Run inside backend/:

    python -m scripts.verify_audit

Checks, each printed as PASS or FAIL:
  a. hash chain: every entry, in id order, by the formula of its own format version (app/security.py),
     so a modified, deleted, reordered or inserted entry fails.
  b. checkpoint signatures: CHECKPOINT_DIR/audit.jsonl exists and every line is well formed and
     signed with the checkpoint key (scripts/audit_checkpoint.py writes them).
  c. checkpoints against the log: the entry at each checkpoint's count still carries that
     checkpoint's head hash, so a log rewritten from the start, or cut short below a checkpoint,
     fails even though its own links might hold.

Then the entry count and head hash, and exit code 1 on any failure. Read only: it uses the
checkpoint public key and changes nothing, not even the audit log it is checking. There is no
option to skip a check. The SR-05 auditor route (GET /api/admin/audit-log/verify) still checks
the chain alone.
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import func, select
from sqlalchemy.orm import Session

# SR-16: the SR-13 checkpoint key, message and reader, reused with the audit log's own tag and fields
from app.ballot_chain import load_checkpoint_public_key, read_checkpoints
from app.config import settings
from app.db import SessionLocal
from app.models import AuditLogEntry
from app.security import audit_hash_at, verify_audit_chain

AUDIT_CHECKPOINT_TAG = b"evoting-audit-checkpoint-v1\n"
AUDIT_CHECKPOINT_FIELDS: dict[str, type] = {"entry_count": int, "head_hash": str}

CHAIN = "a. hash chain"
SIGNATURES = "b. checkpoint signatures"
AGAINST_LOG = "c. checkpoints against the log"


def audit_checkpoint_file() -> Path:
    # SR-16: next to the ballot chain's checkpoints (SR-13), outside the database, never committed
    return settings.backend_path(settings.checkpoint_dir) / "audit.jsonl"


def audit_head(db: Session) -> tuple[int, str | None]:
    """SR-16: how many entries the log holds and the last one's hash (hex), read in one statement."""
    count, head = db.execute(
        select(
            func.count(),
            select(AuditLogEntry.hash).order_by(AuditLogEntry.id.desc()).limit(1).scalar_subquery(),
        ).select_from(AuditLogEntry)
    ).one()
    return count, head.hex() if head is not None else None


def verify_audit(db: Session, public_key: Ed25519PublicKey, path: Path) -> dict[str, str | None]:
    """SR-16: each check's problem, or None when it passes."""
    results: dict[str, str | None] = {}
    checked, first_bad = verify_audit_chain(db)
    results[CHAIN] = None if first_bad is None else f"the chain breaks at entry {first_bad} (verified up to there: {checked})"

    if not path.is_file():
        results[SIGNATURES] = "no audit checkpoints yet: run python -m scripts.audit_checkpoint"
        results[AGAINST_LOG] = "no checkpoint to compare the log against"
        return results
    valid, problems = read_checkpoints(path, public_key, AUDIT_CHECKPOINT_FIELDS, AUDIT_CHECKPOINT_TAG)
    results[SIGNATURES] = ", ".join(sorted(problems)) or (None if valid else "the checkpoint file holds no checkpoint")

    entries, _ = audit_head(db)
    mismatches = []
    for checkpoint in valid:
        position = checkpoint["entry_count"]
        if position > entries:
            mismatches.append(f"the log has {entries} entries, fewer than a checkpoint's {position} (cut short)")
            continue
        stored = audit_hash_at(db, position)
        if stored is None or stored.hex() != checkpoint["head_hash"]:
            mismatches.append(f"entry {position} no longer has the hash its checkpoint signed")
    results[AGAINST_LOG] = "; ".join(mismatches) or (None if valid else "no valid checkpoint to compare against")
    return results


def main(argv: list[str] | None = None) -> int:
    print("SR-16 audit log verification")
    public_path = settings.backend_path(settings.checkpoint_public_key)
    if not public_path.is_file():
        print(f"FAIL     checkpoint public key not found ({public_path.name}); the checkpoints cannot be checked")
        print("SR-16 audit verification: FAIL")
        return 1
    with SessionLocal() as db:
        results = verify_audit(db, load_checkpoint_public_key(public_path), audit_checkpoint_file())
        entries, head = audit_head(db)
    for check, problem in results.items():
        print(f"FAIL     {check}: {problem}" if problem else f"PASS     {check}")
    print(f"Entries: {entries}. Head hash: {head or 'none (the log is empty)'}")
    failed = sum(problem is not None for problem in results.values())
    print("SR-16 audit verification: PASS" if not failed else f"SR-16 audit verification: FAIL ({failed} checks)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
