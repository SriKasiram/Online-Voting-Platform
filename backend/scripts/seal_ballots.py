"""
SR-13: seals an election's accepted but unsealed ballots into its hash chain, as one shuffled batch.
Run inside backend/:

    python -m scripts.seal_ballots --election <election id>            # needs at least MIN_SEAL_BATCH ballots
    python -m scripts.seal_ballots --election <election id> --final    # after polls close: any number, last batch

One transaction, under a per-election advisory lock so two seals cannot interleave: the unsealed
ballots are ordered by their random ballot id (never arrival order or time), given the next
positions and batch number, and chained. After the commit a signed checkpoint line is appended to
CHECKPOINT_DIR/<election id>.jsonl, and the whole chain is verified. No background worker: the
returning officer runs this. The private key is used here and in tests only, never under app/.
"""

import argparse
import base64
import hashlib
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.ballot_chain import (
    CHECKPOINT_TAG,
    checkpoint_file,
    checkpoint_message,
    compute_entry_hash,
    load_checkpoint_public_key,
    read_checkpoints,
    start_hash,
    verify_chain,
)
from app.ballot_definitions import canonical
from app.config import settings
from app.db import SessionLocal
from app.audit_events import FAILURE, SCRIPT, SUCCESS
from app.models import BallotChainEntry
from app.security import audit


class SealRefused(Exception):
    """SR-13: nothing was sealed, for the reason given."""


@dataclass
class SealResult:
    batch_no: int
    count: int
    first_position: int
    entry_count: int
    head_hash: str
    final: bool
    reasons: list[str]


def lock_key(election_id: uuid.UUID) -> int:
    # SR-13: one advisory lock per election, so two seals of the same election take turns
    return int.from_bytes(hashlib.sha256(b"evoting-ballot-chain-lock|" + str(election_id).encode()).digest()[:8], "big", signed=True)


def record_failure(db: Session, reasons: list[str]) -> None:
    # SR-13: the reason codes only, never a hash or a ballot id
    # SR-16: one entry per reason, because a reason is a single catalogued code, not a list
    for reason in reasons:
        audit(db, "BALLOT_CHAIN_VERIFY_FAILED", outcome=FAILURE, actor=SCRIPT, role=SCRIPT, reason=reason)
    db.commit()


def seal_batch(
    db: Session,
    election_id: uuid.UUID,
    final: bool,
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    checkpoint_path: Path,
) -> SealResult:
    """SR-13: seals one batch and writes its checkpoint. Raises SealRefused, changing nothing, when it must not."""
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key(election_id)})
    earlier = read_checkpoints(checkpoint_path, public_key)[0] if checkpoint_path.is_file() else []
    if any(checkpoint["final"] for checkpoint in earlier):
        db.rollback()
        raise SealRefused("this election already had its final seal; no more ballots may be sealed")
    # SR-13: never sign a new head on top of a chain that already fails verification
    problems = verify_chain(db, election_id, public_key, checkpoint_path)
    if problems:
        db.rollback()
        record_failure(db, problems)
        raise SealRefused(f"the existing chain does not verify ({', '.join(problems)}); nothing was sealed")

    tail = db.execute(
        text("SELECT position, batch_no, entry_hash FROM ballot_chain WHERE election_id = :e ORDER BY position DESC LIMIT 1"),
        {"e": election_id},
    ).first()
    # SR-13: ordered by the random ballot id, so a position reveals nothing about arrival (SR-12)
    unsealed = db.execute(
        text(
            "SELECT b.id, b.encrypted_payload FROM ballots b WHERE b.election_id = :e "
            "AND NOT EXISTS (SELECT 1 FROM ballot_chain c WHERE c.ballot_id = b.id) ORDER BY b.id"
        ),
        {"e": election_id},
    ).all()
    if not unsealed:
        db.rollback()
        raise SealRefused("there are no unsealed ballots for this election")
    if len(unsealed) < settings.min_seal_batch and not final:
        db.rollback()
        raise SealRefused(
            f"only {len(unsealed)} unsealed ballot(s); a batch needs at least MIN_SEAL_BATCH={settings.min_seal_batch} "
            "(use --final once polls have closed)"
        )

    # SR-13: make sure the checkpoint can be written before anything is committed, so a missing,
    # read-only or too-long path refuses the seal instead of leaving a batch without its checkpoint
    try:
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        with checkpoint_path.open("a", encoding="utf-8"):
            pass
    except OSError as problem:
        db.rollback()
        raise SealRefused(f"the checkpoint file cannot be written ({problem.strerror}); nothing was sealed") from None

    position = tail.position if tail else 0
    batch_no = (tail.batch_no if tail else 0) + 1
    prev_hash = tail.entry_hash if tail else start_hash(election_id)
    first_position = position + 1
    for ballot_id, encrypted_payload in unsealed:
        position += 1
        entry_hash = compute_entry_hash(prev_hash, ballot_id, election_id, encrypted_payload)
        db.add(
            BallotChainEntry(
                election_id=election_id,
                position=position,
                batch_no=batch_no,
                ballot_id=ballot_id,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
        )
        prev_hash = entry_hash
    # SR-13: the batch number and how many, nothing that names a ballot
    # SR-16: in the seal's transaction: if the entry cannot be written, nothing is sealed
    audit(db, "BALLOT_BATCH_SEALED", outcome=SUCCESS, actor=SCRIPT, role=SCRIPT, batch_no=batch_no, count=len(unsealed))
    db.commit()

    # SR-13: after the commit. If this step is lost the next verification reports tail_mismatch.
    content = {"election_id": str(election_id), "batch_no": batch_no, "entry_count": position, "head_hash": prev_hash, "final": final}
    append_checkpoint(checkpoint_path, content, private_key)

    reasons = verify_chain(db, election_id, public_key, checkpoint_path)
    if reasons:
        record_failure(db, reasons)
    return SealResult(batch_no, len(unsealed), first_position, position, prev_hash, final, reasons)


def append_checkpoint(path: Path, content: dict[str, Any], private_key: Ed25519PrivateKey, tag: bytes = CHECKPOINT_TAG) -> None:
    """
    SR-13: signs one checkpoint and appends it to the file as a JSON line, with a base64 signature.
    SR-16: shared with scripts/audit_checkpoint.py, which passes the audit log's own tag.
    """
    signature = base64.b64encode(private_key.sign(checkpoint_message(content, tag))).decode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as file:
        file.write(canonical(content | {"signature": signature}) + "\n")


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path} is not an Ed25519 private key")
    return key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-13: seal unsealed ballots into the election's hash chain")
    parser.add_argument("--election", type=uuid.UUID, required=True, help="the election id")
    parser.add_argument("--final", action="store_true", help="the last seal, after polls close: any batch size")
    args = parser.parse_args(argv)
    private_path = settings.backend_path(settings.checkpoint_private_key)
    public_path = settings.backend_path(settings.checkpoint_public_key)
    if not private_path.is_file() or not public_path.is_file():
        print(f"REFUSED: checkpoint keys not found ({private_path.name}, {public_path.name}). Create them with: python -m scripts.gen_checkpoint_key")
        return 1
    path = checkpoint_file(args.election)
    with SessionLocal() as db:
        try:
            result = seal_batch(db, args.election, args.final, load_private_key(private_path), load_checkpoint_public_key(public_path), path)
        except SealRefused as refused:
            print(f"REFUSED: {refused}")
            return 1
    print(
        f"Sealed batch {result.batch_no}: {result.count} ballot(s) at positions {result.first_position}-{result.entry_count}, "
        "in ballot id order."
    )
    print(f"Checkpoint appended to {path}")
    print(f"Head hash: {result.head_hash}")  # SR-13: printed on purpose, to be recorded with the release
    print("Verification: PASS" if not result.reasons else f"Verification: FAIL ({', '.join(result.reasons)})")
    if result.final:
        print("Final seal: no more ballots may be accepted for this election.")
    return 0 if not result.reasons else 1


if __name__ == "__main__":
    sys.exit(main())
