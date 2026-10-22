"""
SR-11: creates the AES-256 key that encrypts every stored ballot. Run inside backend/:

    python -m scripts.gen_ballot_key            # writes keys/ballot.key (BALLOT_KEY_FILE)
    python -m scripts.gen_ballot_key --force    # replaces it: every ballot stored so far becomes unreadable

keys/ is in .gitignore, like the SR-02 roll keys. Back the key up somewhere safe and separate from
the database: without it no stored ballot can ever be read again.
"""

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

WARNING = """
WARNING: back this key up now, somewhere safe and separate from the database.
Losing it makes every stored ballot unreadable, and nobody can recover them.
Never commit it, email it or copy it into the project's documents. keys/ is in .gitignore.
"""


def generate_ballot_key(path: Path, force: bool = False) -> Path:
    """SR-11: writes 32 random bytes to path, owner-only (0600) where the OS supports it. Never overwrites unless force."""
    if path.exists() and not force:
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # SR-11: created owner-only, never readable by others even for a moment
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(AESGCM.generate_key(bit_length=256))
    os.chmod(path, 0o600)  # also when --force replaced an older, wider file
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="SR-11: create the AES-256 ballot encryption key")
    parser.add_argument("--force", action="store_true", help="replace an existing key (stored ballots become unreadable)")
    args = parser.parse_args()
    path = settings.ballot_key_file
    try:
        generate_ballot_key(path, force=args.force)
    except FileExistsError:
        raise SystemExit(
            f"{path} already exists. Nothing changed. Replacing it makes every stored ballot unreadable;"
            " use --force only if that is what you want."
        )
    print(f"Created the ballot key at {path} (32 random bytes, AES-256).")
    print(WARNING)


if __name__ == "__main__":
    main()
