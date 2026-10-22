"""
SR-07: the delegates' tool for ballot definitions: build, sign and activate.

Run from the backend folder, with the virtual environment active:
    python -m scripts.ballot_definition build --valid-from 2026-11-01T00:00:00+11:00 \
        --valid-until 2027-11-01T00:00:00+11:00 --out definition.json
    python -m scripts.ballot_definition sign --definition definition.json --delegate delegate_a
    python -m scripts.ballot_definition activate --definition definition.json \
        --signature definition.json.delegate_a.sig.json --signature definition.json.delegate_b.sig.json

DEVELOPMENT KEYS ONLY. The first use creates the private keys of delegate_a,
delegate_b and delegate_c in backend/keys/delegates/ (which Git ignores), and
keyring.json with their public keys. Real delegates would each hold their own
key on protected hardware after a key ceremony, and only the keyring would
reach the API server. Nothing under app/ imports this file.
"""

import argparse
import base64
import hashlib
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.ballot_definitions import OK, active_definition, canonical, message, payload_hash, verify_definition
from app.config import settings
from app.db import SessionLocal
from app.models import BallotDefinition, Candidate, Division, Election
from app.security import audit, utc_now
from scripts.sign_roll import load_or_create_private_key

DELEGATES = ("delegate_a", "delegate_b", "delegate_c")


def key_id_for(public_key: Ed25519PublicKey) -> str:
    # SR-07: a short fingerprint of the public key, so a key_id cannot be reused for another key
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def write_keyring(path: Path, keys: list[tuple[str, Ed25519PrivateKey]]) -> None:
    """SR-07: writes the public half of each (delegate, key) pair. One delegate may hold several keys."""
    ring = {
        key_id_for(key.public_key()): {
            "delegate": delegate,
            "public_key": key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode(),
        }
        for delegate, key in keys
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ring, indent=2, sort_keys=True), encoding="utf-8")


def ensure_delegate_keys(folder: Path | None = None) -> dict[str, Ed25519PrivateKey]:
    """
    SR-07: DEVELOPMENT KEYS ONLY. Loads the three delegates' private keys from
    the keyring's folder, creating any that are missing, and rewrites the keyring.
    """
    keyring = settings.delegate_keyring_path if folder is None else folder / "keyring.json"
    keys = {d: load_or_create_private_key(keyring.parent / f"{d}.pem", keyring.parent / f"{d}.pub.pem") for d in DELEGATES}
    write_keyring(keyring, list(keys.items()))
    return keys


def divisions_of(db: Session, election: Election) -> list[dict]:
    # SR-07: every division with candidates in this election, each with its candidates in ballot order
    rows = db.execute(
        select(Candidate, Division)
        .join(Division, Division.id == Candidate.division_id)
        .where(Candidate.election_id == election.id)
        .order_by(Division.id, Candidate.ballot_position)
    ).all()
    divisions: dict[int, dict] = {}
    for candidate, division in rows:
        entry = divisions.setdefault(
            division.id, {"division_id": division.id, "name": division.name, "state": division.state, "candidates": []}
        )
        entry["candidates"].append(
            {
                "candidate_id": candidate.id,
                "given_name": candidate.given_name,
                "surname": candidate.surname,
                "party": candidate.party,
                "ballot_position": candidate.ballot_position,
            }
        )
    return list(divisions.values())


def build_payload(db: Session, election: Election, valid_from: datetime, valid_until: datetime) -> str:
    """SR-07: the next version's canonical payload, from the election's current candidates."""
    active = active_definition(db, election.id)
    return canonical(
        {
            "election_id": str(election.id),
            "version": active.version + 1 if active else 1,
            "prev_hash": payload_hash(active.payload) if active else None,
            "valid_from": valid_from.isoformat(),
            "valid_until": valid_until.isoformat(),
            "divisions": divisions_of(db, election),
        }
    )


def sign(key: Ed25519PrivateKey, payload: str) -> dict[str, str]:
    # SR-07: one delegate's approval of this exact payload
    return {"key_id": key_id_for(key.public_key()), "signature": base64.b64encode(key.sign(message(payload))).decode()}


def store_active(db: Session, election_id: uuid.UUID, payload: str, signatures: list, activated_at: datetime) -> None:
    """SR-07: retires the active version and adds this one as active. Old payloads are never changed."""
    db.execute(
        update(BallotDefinition)
        .where(BallotDefinition.election_id == election_id, BallotDefinition.is_active)
        .values(is_active=False)
        .execution_options(synchronize_session=False)
    )
    db.add(
        BallotDefinition(
            election_id=election_id,
            version=json.loads(payload)["version"],
            payload=payload,
            signatures=signatures,
            is_active=True,
            activated_at=activated_at,
        )
    )
    db.flush()


def activate(db: Session, payload: str, signatures: list) -> str:
    """
    SR-07: in one transaction, activates the definition if it verifies, is the
    active version + 1 with the right prev_hash, and polls open no sooner than
    MIN_ACTIVATION_LEAD_HOURS from now. Otherwise changes nothing. Returns "ok"
    or the reason code, and audits either way (no payload or signature material).
    """
    now = utc_now()
    try:
        election_id = uuid.UUID(json.loads(payload)["election_id"])
    except (ValueError, TypeError, KeyError, AttributeError):
        election_id = None
    # Locking the election serialises activations, even before any version exists
    election = db.get(Election, election_id, with_for_update=True) if election_id else None
    if election_id is None:
        reason = "bad_payload"
    elif election is None:
        reason = "unknown_election"
    else:
        reason = verify_definition(payload, signatures, election.id, active_definition(db, election.id))
        if reason == OK and now >= election.starts_at:
            reason = "polls_open"
        elif reason == OK and now > election.starts_at - timedelta(hours=settings.min_activation_lead_hours):
            reason = "insufficient_lead"
    if reason != OK:
        db.rollback()
        audit(db, "BALLOT_DEFINITION_REJECTED", actor="script", reason=reason)
        db.commit()
        return reason
    store_active(db, election.id, payload, signatures, now)
    audit(db, "BALLOT_DEFINITION_ACTIVATED", actor="script")
    db.commit()
    return OK


def read_text(path: Path) -> str:
    # The exact bytes, with no newline translation
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise SystemExit(f"Could not read {path}: {error}") from None


def write_text(path: Path, text: str) -> None:
    # SR-07: the exact bytes; a file that cannot be written ends the command with a reason, not a traceback
    try:
        path.write_bytes(text.encode("utf-8"))
    except OSError as error:
        raise SystemExit(f"Could not write {path}: {error}") from None


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Build, sign and activate ballot definitions (SR-07).")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="write the next version's payload to a file")
    build.add_argument("--election", type=uuid.UUID, help="the election's id (default: the latest election)")
    build.add_argument("--valid-from", type=datetime.fromisoformat, required=True)
    build.add_argument("--valid-until", type=datetime.fromisoformat, required=True)
    build.add_argument("--out", type=Path, required=True)
    sign_command = commands.add_parser("sign", help="sign a payload file as one delegate")
    sign_command.add_argument("--definition", type=Path, required=True)
    sign_command.add_argument("--delegate", choices=DELEGATES, required=True)
    sign_command.add_argument("--out", type=Path)
    activate_command = commands.add_parser("activate", help="verify and activate a signed payload")
    activate_command.add_argument("--definition", type=Path, required=True)
    activate_command.add_argument("--signature", type=Path, action="append", required=True)
    args = parser.parse_args(argv)

    if args.command == "build":
        if not args.valid_from.tzinfo or not args.valid_until.tzinfo:
            raise SystemExit("--valid-from and --valid-until need a time zone, such as +11:00.")
        if args.valid_until <= args.valid_from:
            raise SystemExit("--valid-until must be after --valid-from.")
        with SessionLocal() as db:
            latest = select(Election).order_by(Election.starts_at.desc())
            election = db.get(Election, args.election) if args.election else db.scalars(latest).first()
            if election is None:
                raise SystemExit("There is no such election.")
            payload = build_payload(db, election, args.valid_from, args.valid_until)
            name = election.name
        write_text(args.out, payload)
        print(f"Wrote version {json.loads(payload)['version']} of the ballot definition for {name} to {args.out}.")
    elif args.command == "sign":
        payload = read_text(args.definition)
        out = args.out or args.definition.with_name(f"{args.definition.name}.{args.delegate}.sig.json")
        write_text(out, json.dumps(sign(ensure_delegate_keys()[args.delegate], payload)))
        print(f"{args.delegate} signed {args.definition}. Signature: {out}")
    else:
        payload = read_text(args.definition)
        try:
            signatures = [json.loads(read_text(path)) for path in args.signature]
        except ValueError as error:
            raise SystemExit(f"A signature file is not valid JSON: {error}") from None
        with SessionLocal() as db:
            reason = activate(db, payload, signatures)
        if reason != OK:
            raise SystemExit(f"Rejected: {reason}")
        print(f"Activated version {json.loads(payload)['version']}.")


if __name__ == "__main__":
    main()
