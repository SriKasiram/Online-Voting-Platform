"""
SR-13: the SHA-256 hash chain over each election's accepted ballots, its signed checkpoints, and the
one verification that the seal and verify scripts (and any future count) must use.

Encodings. Every part is ASCII text: UUIDs as str(uuid) (lowercase, hyphenated), hashes as lowercase
hex SHA-256.
- Start value: sha256(b"evoting-ballot-chain-start-v1|" + election_id)
- Entry hash:  sha256(b"evoting-ballot-chain-v1|" + prev_hash + b"|" + ballot_id + b"|" + election_id
                      + b"|" + sha256(encrypted_payload))
  prev_hash is the previous entry's hash, or the start value for position 1. encrypted_payload is the
  stored SR-11 ciphertext, so verifying never decrypts a ballot or reads its content.
- Checkpoint:  Ed25519 over b"evoting-ballot-checkpoint-v1\\n" + canonical JSON (SR-07's canonical:
  sorted keys, compact) of {election_id, batch_no, entry_count, head_hash, final}. Stored as JSON
  Lines in CHECKPOINT_DIR/<election_id>.jsonl, one line per sealed batch, with a base64 "signature".

The server side reads only the public key here. The private key belongs to scripts/seal_ballots.py.
"""

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import text
from sqlalchemy.orm import Session

# SR-13: SR-07's canonical JSON and the shared Ed25519 helpers, reused rather than copied
from app.ballot_definitions import canonical
from app.config import settings
# SR-13, SR-16: the shared public key loader and Ed25519 check (app/key_files.py)
from app.key_files import load_public_key_file, verify_signature

START_TAG = b"evoting-ballot-chain-start-v1|"
ENTRY_TAG = b"evoting-ballot-chain-v1|"
CHECKPOINT_TAG = b"evoting-ballot-checkpoint-v1\n"
CHECKPOINT_FIELDS = {"election_id": str, "batch_no": int, "entry_count": int, "head_hash": str, "final": bool}

# SR-13: every reason verify_chain can give, by the check group the verify script prints
CHECK_GROUPS = {
    "a. entry hashes and links": ("bad_entry_hash", "broken_link"),
    "b. positions": ("gap_or_reorder",),
    "c. ballots": ("missing_ballot",),
    "d. checkpoint signatures": ("missing_checkpoint", "malformed_checkpoint", "bad_checkpoint_signature"),
    "e. checkpoints against the chain": ("checkpoint_mismatch", "tail_mismatch"),
    "f. nothing unsealed after the final seal": ("unsealed_after_final",),
}


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def start_hash(election_id: UUID | str) -> str:
    """SR-13: the value position 1 links back to, different for every election."""
    return _sha256_hex(START_TAG + str(election_id).encode("ascii"))


def compute_entry_hash(prev_hash: str, ballot_id: UUID | str, election_id: UUID | str, encrypted_payload: bytes) -> str:
    """SR-13: one link. Changing the ballot's bytes, its id, its election or anything before it changes this."""
    parts = (prev_hash, str(ballot_id), str(election_id), _sha256_hex(bytes(encrypted_payload)))
    return _sha256_hex(ENTRY_TAG + b"|".join(part.encode("ascii") for part in parts))


def checkpoint_message(content: dict[str, Any], tag: bytes = CHECKPOINT_TAG) -> bytes:
    """SR-13: exactly what the checkpoint key signs.
    SR-16: the audit log's checkpoints pass their own tag, so a ballot checkpoint can never pass as an
    audit one or the other way round."""
    return tag + canonical(content).encode("utf-8")


def checkpoint_file(election_id: UUID | str) -> Path:
    return settings.backend_path(settings.checkpoint_dir) / f"{election_id}.jsonl"


def load_checkpoint_public_key(path: Path) -> Ed25519PublicKey:
    """SR-13: read only when verifying, so the API starts without it (CI and tests have none)."""
    return load_public_key_file(path)


def read_checkpoints(
    path: Path,
    public_key: Ed25519PublicKey,
    fields: dict[str, type] = CHECKPOINT_FIELDS,
    tag: bytes = CHECKPOINT_TAG,
) -> tuple[list[dict[str, Any]], set[str]]:
    """SR-13: the checkpoint lines whose signature holds, in file order, and the problems with the rest.
    SR-16: also reads the audit log's checkpoints, which have their own fields and tag."""
    valid: list[dict[str, Any]] = []
    problems: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            signature = base64.b64decode(record.pop("signature"), validate=True)
            well_formed = set(record) == set(fields) and all(type(record[name]) is kind for name, kind in fields.items())
        except (ValueError, KeyError, AttributeError, TypeError, binascii.Error):
            well_formed = False
        if not well_formed:
            problems.add("malformed_checkpoint")
        elif not verify_signature(public_key, signature, checkpoint_message(record, tag)):
            problems.add("bad_checkpoint_signature")
        else:
            valid.append(record)
    return valid, problems


def verify_chain(session: Session, election_id: UUID | str, public_key: Ed25519PublicKey, checkpoint_path: Path) -> list[str]:
    """
    SR-13: checks an election's chain, its ballots and its signed checkpoints. Returns the reason
    codes found, sorted; an empty list means the chain verifies. Unsealed ballots are normal until a
    final seal. Reads ciphertext only: no ballot is decrypted.
    """
    election = str(UUID(str(election_id)))
    reasons: set[str] = set()
    entries = session.execute(
        text(
            "SELECT c.position, c.batch_no, c.ballot_id, c.prev_hash, c.entry_hash, "
            "b.encrypted_payload, b.election_id AS ballot_election "
            "FROM ballot_chain c LEFT JOIN ballots b ON b.id = c.ballot_id "
            "WHERE c.election_id = :election ORDER BY c.position"
        ),
        {"election": election},
    ).all()

    # b. positions 1, 2, 3 ... with no gap, and batch numbers that start at 1 and never go back or skip
    batches = [entry.batch_no for entry in entries]
    if [entry.position for entry in entries] != list(range(1, len(entries) + 1)) or (
        batches and (batches[0] != 1 or any(b - a not in (0, 1) for a, b in zip(batches, batches[1:])))
    ):
        reasons.add("gap_or_reorder")

    # a, c. each entry links to the one before and matches its stored ballot
    expected_prev = start_hash(election)
    for entry in entries:
        if entry.prev_hash != expected_prev:
            reasons.add("broken_link")
        if entry.encrypted_payload is None:
            reasons.add("missing_ballot")
        elif str(entry.ballot_election) != election or entry.entry_hash != compute_entry_hash(
            entry.prev_hash, entry.ballot_id, election, entry.encrypted_payload
        ):
            reasons.add("bad_entry_hash")
        expected_prev = entry.entry_hash

    # d, e. signed checkpoints, each matching the chain as it was when that batch was sealed
    checkpoints: list[dict[str, Any]] = []
    if checkpoint_path.is_file():
        checkpoints, problems = read_checkpoints(checkpoint_path, public_key)
        reasons |= problems
        for number, checkpoint in enumerate(checkpoints, start=1):
            sealed = [entry for entry in entries if entry.batch_no <= checkpoint["batch_no"]]
            head = sealed[-1].entry_hash if sealed else None
            if (
                checkpoint["election_id"] != election
                or checkpoint["batch_no"] != number
                or (checkpoint["final"] and number != len(checkpoints))
                or checkpoint["entry_count"] != len(sealed)
                or checkpoint["head_hash"] != head
            ):
                reasons.add("checkpoint_mismatch")
        last = checkpoints[-1] if checkpoints else None
        tail = entries[-1] if entries else None
        if (last is None) != (tail is None) or (
            last is not None
            and tail is not None
            and (last["entry_count"] != len(entries) or last["head_hash"] != tail.entry_hash or last["batch_no"] != tail.batch_no)
        ):
            reasons.add("tail_mismatch")
    elif entries:
        reasons.add("missing_checkpoint")

    # f. after a final seal every ballot of the election must be in the chain
    if any(checkpoint["final"] for checkpoint in checkpoints):
        unsealed = session.scalar(
            text(
                "SELECT count(*) FROM ballots b WHERE b.election_id = :election "
                "AND NOT EXISTS (SELECT 1 FROM ballot_chain c WHERE c.ballot_id = b.id)"
            ),
            {"election": election},
        )
        if unsealed:
            reasons.add("unsealed_after_final")
    return sorted(reasons)
