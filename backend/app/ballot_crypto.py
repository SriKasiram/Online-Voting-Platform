"""
SR-11: every stored ballot is encrypted at rest with AES-256-GCM.

Stored format, one bytes column (ballots.encrypted_payload):

    0x01 (format version) | 12-byte random nonce | ciphertext with its 16-byte GCM tag

The plaintext is the whole ballot (the division and the ranking) as canonical
JSON. The associated data is "{ballot_id}|{election_id}", so a ciphertext
copied to another ballot row or election does not decrypt. The key is 32
random bytes in BALLOT_KEY_FILE (python -m scripts.gen_ballot_key). Nothing
here logs or prints the key, a plaintext ballot or a ciphertext.
"""

import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

FORMAT_VERSION = 0x01
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32
MIN_BLOB_BYTES = 1 + NONCE_BYTES + TAG_BYTES

# SR-11: the payload's field names. The pre-release audit scans logs for them.
DIVISION_FIELD = "division_id"
RANKING_FIELD = "ranked_candidate_ids"
PAYLOAD_FIELDS = (DIVISION_FIELD, RANKING_FIELD)


class BallotKeyError(RuntimeError):
    """SR-11: the ballot key is missing or unusable. The API refuses to start; there is no fallback."""


class BallotDecryptionError(ValueError):
    """SR-11: a stored ballot did not open: wrong key, altered bytes, another row or election, or unknown format."""


def ballot_payload(division_id: int, ranking: list[int]) -> dict[str, Any]:
    """SR-11: everything a ballot says, so all of it is encrypted together."""
    return {DIVISION_FIELD: division_id, RANKING_FIELD: list(ranking)}


def load_key(path: Path) -> bytes:
    """
    SR-11: reads the AES-256 key, failing closed. The file must exist, hold exactly 32 bytes and,
    on POSIX systems, give no access to group or others. Windows has no such mode bits, so the
    permission check is skipped there.
    """
    path = Path(path)
    if not path.is_file():
        raise BallotKeyError(f"No ballot key at {path}. Create it with: python -m scripts.gen_ballot_key")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise BallotKeyError(f"The ballot key {path} can be read by other users. Run: chmod 600 {path}")
    key = path.read_bytes()
    if len(key) != KEY_BYTES:
        raise BallotKeyError(f"The ballot key {path} must be exactly {KEY_BYTES} bytes (AES-256), not {len(key)}")
    return key


def check_ballot_key_at_startup() -> None:
    """SR-11: the API does not start without a usable ballot key: no default key and no plaintext mode."""
    load_key(settings.ballot_key_file)


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _associated_data(ballot_id: UUID, election_id: UUID) -> bytes:
    # SR-11: binds the ciphertext to its own row and election
    return f"{ballot_id}|{election_id}".encode()


def encrypt_ballot(payload: dict[str, Any], ballot_id: UUID, election_id: UUID) -> bytes:
    """SR-11: version byte, a fresh random nonce, then the AES-256-GCM ciphertext and tag."""
    # SR-11: never reused and never derived from anything: 12 bytes from the OS random source
    nonce = os.urandom(NONCE_BYTES)
    sealed = AESGCM(load_key(settings.ballot_key_file)).encrypt(
        nonce, _canonical(payload), _associated_data(ballot_id, election_id)
    )
    return bytes([FORMAT_VERSION]) + nonce + sealed


def decrypt_ballot(blob: bytes, ballot_id: UUID, election_id: UUID) -> dict[str, Any]:
    """SR-11: opens a stored ballot in memory only. Raises BallotDecryptionError if it cannot."""
    blob = bytes(blob)
    if len(blob) < MIN_BLOB_BYTES:
        raise BallotDecryptionError("too short to be an encrypted ballot")
    if blob[0] != FORMAT_VERSION:
        # SR-11: the byte is not shown: in a plaintext row it would be the ballot's first character
        raise BallotDecryptionError("unknown ballot format version")
    nonce, sealed = blob[1 : 1 + NONCE_BYTES], blob[1 + NONCE_BYTES :]
    try:
        plaintext = AESGCM(load_key(settings.ballot_key_file)).decrypt(
            nonce, sealed, _associated_data(ballot_id, election_id)
        )
    except InvalidTag:
        # SR-11: one message for every cause, and no bytes of the ballot in it
        raise BallotDecryptionError("did not decrypt: wrong key, altered data, or another ballot or election") from None
    payload: dict[str, Any] = json.loads(plaintext)
    return payload
