"""
SR-18: the canonical House result dataset that a release signs, and the results key's fingerprint.

build_dataset returns the exact bytes that are signed and released: JSON with sorted keys, compact
separators (",", ":"), real UTF-8 rather than \\u escapes, and no trailing newline. The same inputs
always give the same bytes, so a recipient's file is byte-for-byte what was signed.

Only public-key code lives here. The private key is read by scripts/release_results.py alone.
"""

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# SR-18: SR-07's canonical JSON (sorted keys, compact, ensure_ascii=False), reused rather than copied
from app.ballot_definitions import canonical
from app.roll_signing import parse_public_key

SCHEMA = "evoting-house-result-v1"


def key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """
    SR-18: the results key's fingerprint: the SHA-256, as lowercase hex, of the raw 32-byte Ed25519
    public key (not of its PEM text, whose line breaks and headers can differ between tools).
    """
    return hashlib.sha256(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()


def load_results_public_key(path: Path) -> Ed25519PublicKey:
    """SR-18: the published results key. Read only to serve and verify, so the app starts without it."""
    return parse_public_key(Path(path).read_bytes())


def build_dataset(
    count_result: dict[str, Any],
    *,
    release_version: int,
    previous_release_sha256: str | None,
    generated_at: datetime,
    signing_key_fingerprint: str,
) -> bytes:
    """
    SR-18: the dataset for one release, from a fresh SR-17 count result. Totals only: the SR-17
    result holds no ballot id, ranking, token or receipt, and nothing else is added here.
    """
    dataset = {
        "schema": SCHEMA,
        "election_id": count_result["election_id"],
        "release_version": release_version,
        # SR-18: each release names the one before, so a correction can never silently replace it
        "previous_release_sha256": previous_release_sha256,
        "generated_at": generated_at.isoformat(),
        "final_chain_head": count_result["final_checkpoint"]["head_hash"],
        "ballot_count": count_result["ballots_counted"],
        "signing_key_fingerprint": signing_key_fingerprint,
        "divisions": [
            {
                "division_id": division["division_id"],
                "division": division["division"],
                "formal_total": division["formal_total"],
                "rounds": division["rounds"],
                "elected": division["elected"],
                "status": division["status"],
            }
            for division in count_result["divisions"]
        ],
    }
    return canonical(dataset).encode("utf-8")
