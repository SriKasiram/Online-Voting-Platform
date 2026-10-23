"""
SR-07: signed ballot definitions. A definition is one canonical JSON payload
with every division's ballot paper for an election, signed with Ed25519 by
delegates whose public keys are in the keyring (DELEGATE_KEYRING_PATH). The app
only ever verifies: building, signing and activating live in
scripts/ballot_definition.py, and no delegate private key is read here.
"""

import base64
import hashlib
import json
import logging
import uuid
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

# SR-16: the start-up check records its failure with the allow-listed fields
from app.audit_events import FAILURE, UNKNOWN
from app.config import settings
from app.models import BallotDefinition, Election, ElectionStatus
from app.roll_signing import parse_public_key, verify_signature
from app.security import audit, utc_now

logger = logging.getLogger(__name__)

# SR-07: binds a signature to this purpose and format version
DOMAIN_TAG = b"evoting-ballot-definition-v1\n"
OK = "ok"


def canonical(content: dict[str, Any]) -> str:
    """SR-07: the one text form of a payload: sorted keys, compact separators, UTF-8."""
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def message(payload: str) -> bytes:
    # SR-07: what the delegates sign: the tag, then the stored payload exactly as it is
    return DOMAIN_TAG + payload.encode("utf-8")


def payload_hash(payload: str) -> str:
    # SR-07: links each version to the one before it
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@lru_cache
def load_keyring(path: Path) -> dict[str, tuple[str, Ed25519PublicKey]]:
    """SR-07: key_id -> (delegate, public key). Public keys only."""
    entries = json.loads(path.read_text(encoding="utf-8"))
    return {key_id: (entry["delegate"], parse_public_key(entry["public_key"].encode())) for key_id, entry in entries.items()}


def verify_definition(payload: str, signatures: Any, election_id: uuid.UUID, previous: BallotDefinition | None) -> str:
    """
    SR-07: "ok", or the first reason the definition must not be used:
    bad_payload, election_mismatch, bad_signature, not_enough_delegates,
    not_yet_valid, expired, bad_version or bad_prev_hash.

    Signatures are checked over the stored payload text, never a re-serialised
    copy. A signature with an unknown key_id or that does not verify does not
    count, and approvals are counted per distinct delegate in the keyring, so a
    repeated signature or two keys of one delegate count once. `previous` is the
    version this one must follow (None for version 1).
    """
    try:
        content = json.loads(payload)
        version, prev_hash, divisions = content["version"], content["prev_hash"], content["divisions"]
        valid_from = datetime.fromisoformat(content["valid_from"])
        valid_until = datetime.fromisoformat(content["valid_until"])
        if not isinstance(version, int) or not isinstance(divisions, list) or not valid_from.tzinfo or not valid_until.tzinfo:
            return "bad_payload"
    except (ValueError, TypeError, KeyError):
        return "bad_payload"
    if content.get("election_id") != str(election_id):
        return "election_mismatch"

    try:
        keyring = load_keyring(settings.delegate_keyring_path)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        keyring = {}
    delegates, rejected = set(), False
    for entry in signatures if isinstance(signatures, list) else []:
        try:
            delegate, key = keyring[entry["key_id"]]
            valid = verify_signature(key, base64.b64decode(entry["signature"], validate=True), message(payload))
        except (KeyError, TypeError, ValueError):
            valid = False
        if valid:
            delegates.add(delegate)
        else:
            rejected = True
    if len(delegates) < settings.required_delegate_approvals:
        return "bad_signature" if rejected else "not_enough_delegates"

    now = utc_now()
    if now < valid_from:
        return "not_yet_valid"
    if now > valid_until:
        return "expired"
    if version != (previous.version + 1 if previous else 1):
        return "bad_version"
    if prev_hash != (payload_hash(previous.payload) if previous else None):
        return "bad_prev_hash"
    return OK


def active_definition(db: Session, election_id: uuid.UUID) -> BallotDefinition | None:
    return db.scalar(
        select(BallotDefinition).where(BallotDefinition.election_id == election_id, BallotDefinition.is_active)
    )


def check_stored(db: Session, definition: BallotDefinition) -> str:
    # SR-07: a stored version is checked against the version before it, which also proves the
    # payload's version matches the row's
    previous = db.scalar(
        select(BallotDefinition).where(
            BallotDefinition.election_id == definition.election_id, BallotDefinition.version == definition.version - 1
        )
    )
    return verify_definition(definition.payload, definition.signatures, definition.election_id, previous)


def verified_division(db: Session, election: Election, division_id: int) -> tuple[dict[str, Any] | None, str]:
    """SR-07: the division's ballot paper from the active definition, verified on every call, or why not."""
    definition = active_definition(db, election.id)
    if definition is None:
        return None, "no_active_definition"
    reason = check_stored(db, definition)
    if reason != OK:
        return None, reason
    for division in json.loads(definition.payload)["divisions"]:
        if division.get("division_id") == division_id:
            return division, OK
    return None, "no_division_entry"


def check_definitions_at_startup(db: Session) -> None:
    """
    SR-07: refuses to start the API unless every election whose polls have not
    closed has a valid active definition. An election that is not open yet may
    still be waiting for one; an open election may not.
    """
    now = utc_now()
    for election in db.scalars(select(Election).where(Election.status == ElectionStatus.OPEN, Election.ends_at > now)):
        definition = active_definition(db, election.id)
        if definition is None and election.starts_at > now:
            continue
        reason = "no_active_definition" if definition is None else check_stored(db, definition)
        if reason != OK:
            logger.error("Ballot definition check failed for election %s: %s", election.id, reason)
            # SR-16: recorded if the database can still take it; the API refuses to start either way
            try:
                audit(db, "BALLOT_DEFINITION_INVALID", outcome=FAILURE, actor=UNKNOWN, role=UNKNOWN, reason=reason)
                db.commit()
            except SQLAlchemyError:
                db.rollback()
                logger.error("The failed ballot definition check could not be written to the audit log")
            raise RuntimeError(f"Refusing to start: election {election.id} has no valid ballot definition ({reason})")
