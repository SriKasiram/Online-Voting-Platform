"""
SR-16: signs the audit log's current head with the SR-13 checkpoint key. Run inside backend/:

    python -m scripts.audit_checkpoint

Reads how many entries the audit log holds and the last entry's hash, signs them over
b"evoting-audit-checkpoint-v1\\n" + canonical JSON {entry_count, head_hash}, and appends one line to
CHECKPOINT_DIR/audit.jsonl. Kept outside the database, each line lets scripts/verify_audit.py
notice a log rewritten, reordered or cut short below it, which the hash chain alone cannot.

It refuses, signing nothing, if the keys are missing, the log is empty, the chain does not verify,
or an earlier checkpoint no longer matches: a checkpoint must never vouch for a tampered log.
Run it before each release, and as often as wanted during an election. The private key is used
here and in the seal script only, never under app/.
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy.orm import Session

from app.ballot_chain import load_checkpoint_public_key
from app.config import settings
from app.db import SessionLocal
# SR-16: the SR-13 checkpoint writer, reused with the audit log's own tag, and the shared key loader
from scripts.seal_ballots import append_checkpoint
from scripts.signing_keys import load_private_key
from scripts.verify_audit import AUDIT_CHECKPOINT_TAG, audit_checkpoint_file, audit_head, verify_audit


class CheckpointRefused(Exception):
    """SR-16: nothing was signed, and why."""


def sign_audit_checkpoint(
    db: Session, private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey, path: Path
) -> dict[str, int | str]:
    """SR-16: verifies the log and the earlier checkpoints, then appends one signed checkpoint."""
    entries, head = audit_head(db)
    if not entries or head is None:
        raise CheckpointRefused("the audit log is empty; there is nothing to sign")
    results = verify_audit(db, public_key, path)
    # A first checkpoint has nothing to be compared with yet; anything else must already pass
    problems = {check: problem for check, problem in results.items() if problem is not None}
    if not path.is_file():
        problems = {check: problem for check, problem in problems.items() if check == "a. hash chain"}
    if problems:
        raise CheckpointRefused("the audit log does not verify (" + "; ".join(f"{c}: {p}" for c, p in problems.items()) + ")")
    content: dict[str, int | str] = {"entry_count": entries, "head_hash": head}
    append_checkpoint(path, content, private_key, AUDIT_CHECKPOINT_TAG)
    return content


def main(argv: list[str] | None = None) -> int:
    private_path = settings.backend_path(settings.checkpoint_private_key)
    public_path = settings.backend_path(settings.checkpoint_public_key)
    if not private_path.is_file() or not public_path.is_file():
        print(f"REFUSED: checkpoint keys not found ({private_path.name}, {public_path.name}). Create them with: python -m scripts.gen_checkpoint_key")
        return 1
    path = audit_checkpoint_file()
    with SessionLocal() as db:
        try:
            content = sign_audit_checkpoint(db, load_private_key(private_path), load_checkpoint_public_key(public_path), path)
        except CheckpointRefused as refused:
            print(f"REFUSED: {refused}")
            return 1
    print(f"Signed an audit checkpoint at {content['entry_count']} entries in {path}.")
    print(f"Head hash: {content['head_hash']}")  # SR-16: on purpose, for the release record
    return 0


if __name__ == "__main__":
    sys.exit(main())
