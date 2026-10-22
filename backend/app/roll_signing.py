"""
SR-02: the signed part of an electoral roll record, and checking its Ed25519
signature with the roll's public key. The private key and the signing code live
in scripts/sign_roll.py, which nothing under app/ imports.
"""

import base64
import json
import logging
from functools import lru_cache
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ElectoralRollEntry
from app.security import audit, decrypt_or_none

logger = logging.getLogger(__name__)

# SR-02: binds a signature to this purpose and format version
DOMAIN_TAG = b"evoting-roll-record-v1"


def record_message(entry: ElectoralRollEntry) -> bytes:
    """
    SR-02: the exact bytes that are signed. Only the fixed eligibility fields:
    nothing that registration or voting changes later (registered_at, the
    enrolment code, its attempts). Sorted keys and compact separators, so the
    same record always gives the same bytes.
    """
    fields = {
        "roll_id": str(entry.id),
        "roll_lookup": base64.b64encode(entry.roll_lookup).decode(),
        "date_of_birth": decrypt_or_none(entry.date_of_birth_enc, "electoral_roll.date_of_birth"),
        "enrolled": entry.enrolled,
        "division_id": entry.division_id,
    }
    return DOMAIN_TAG + b"\n" + json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def parse_public_key(pem: bytes) -> Ed25519PublicKey:
    # SR-07: split out of load_public_key so the ballot definition keyring uses it too
    key = load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


@lru_cache
def load_public_key(path: Path) -> Ed25519PublicKey:
    # SR-02: read once per path. Raises if the file is missing or is not an Ed25519 public key.
    return parse_public_key(path.read_bytes())


def public_key() -> Ed25519PublicKey:
    return load_public_key(settings.roll_public_key_path)


def verify_signature(key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    # SR-07: the one Ed25519 check, shared by roll records (SR-02) and ballot definitions. Never raises.
    try:
        key.verify(signature, message)
    except InvalidSignature:
        return False
    return True


def verify_record(key: Ed25519PublicKey, entry: ElectoralRollEntry) -> bool:
    """SR-02: True only if the record's signature matches its current fields. Never raises on a bad signature."""
    if not entry.record_signature:
        return False
    # SR-07: now through the shared verify_signature; same result as before
    return verify_signature(key, entry.record_signature, record_message(entry))


def check_roll_at_startup(db: Session) -> None:
    """
    SR-02: verifies every roll record before the API starts, and refuses to start
    if the public key is missing or any record fails. This catches a record added
    or changed without the private key. A deleted record is not caught here, but
    it fails safe: that voter is then denied a ballot because they have no record.
    """
    entries = db.scalars(select(ElectoralRollEntry)).all()
    try:
        key = public_key()
    except (OSError, ValueError, UnsupportedAlgorithm):
        key = None
    failed = len(entries) if key is None else sum(not verify_record(key, entry) for entry in entries)
    if key is None or failed:
        # Counts only: never a name or a date of birth
        logger.error(
            "Electoral roll check failed for %d of %d records%s",
            failed,
            len(entries),
            " (public key missing or unreadable)" if key is None else "",
        )
        audit(db, "ROLL_VERIFICATION_FAILED", actor="unknown", records=len(entries), failed=failed)
        db.commit()
        raise RuntimeError(
            f"Refusing to start: the electoral roll failed its signature check ({failed} of {len(entries)} records)"
        )
    audit(db, "ROLL_VERIFIED", actor="unknown", records=len(entries))
    db.commit()
