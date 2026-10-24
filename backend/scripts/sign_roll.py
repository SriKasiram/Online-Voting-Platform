"""
SR-02: signs every electoral roll record with the roll's Ed25519 private key,
so the API can check each record with the public key alone.

Run from the backend folder, with the virtual environment active:
    python -m scripts.sign_roll

DEVELOPMENT KEYS ONLY. The first run creates backend/keys/roll_private.pem and
backend/keys/roll_public.pem, which Git ignores. In a real system the
electoral commission would hold the private key offline or in a hardware
security module, and the API server would only ever receive the public key.

This script signs whatever the roll holds right now, so run it only on a roll
you trust. Nothing under app/ imports this file or the private key.
"""

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import BACKEND_DIR, settings
from app.db import SessionLocal
from app.models import ElectoralRollEntry
from app.roll_signing import record_message
# SR-02: the shared key-pair helper and the one signing call (scripts/signing_keys.py)
from scripts.signing_keys import load_or_create_key_pair, sign

PRIVATE_KEY_PATH = BACKEND_DIR / "keys" / "roll_private.pem"


def load_or_create_private_key(
    private_path: Path = PRIVATE_KEY_PATH, public_path: Path | None = None
) -> Ed25519PrivateKey:
    """
    SR-02: loads the private key, first creating a new development key pair if
    there is none, and writes the matching public key where the API reads it.
    """
    return load_or_create_key_pair(private_path, public_path or settings.roll_public_key_path)


def sign_record(key: Ed25519PrivateKey, entry: ElectoralRollEntry) -> bytes:
    # SR-02: signs the same bytes that app/roll_signing.py verifies
    return sign(key, record_message(entry))


def sign_all(session: Session, key: Ed25519PrivateKey) -> int:
    """SR-02: signs every roll record and commits. Returns how many were signed."""
    entries = session.scalars(select(ElectoralRollEntry)).all()
    for entry in entries:
        entry.record_signature = sign_record(key, entry)
    session.commit()
    return len(entries)


def main() -> None:
    with SessionLocal() as session:
        count = sign_all(session, load_or_create_private_key())
    print(f"Signed {count} electoral roll records. Public key: {settings.roll_public_key_path}")


if __name__ == "__main__":
    main()
