"""
SR-13: creates the Ed25519 key pair that signs the ballot chain checkpoints. Run inside backend/:

    python -m scripts.gen_checkpoint_key            # keys/checkpoint_private.pem and keys/checkpoint_public.pem
    python -m scripts.gen_checkpoint_key --force    # replaces them

DEVELOPMENT KEYS ONLY, like the SR-02 and SR-07 keys: keys/ is in .gitignore. Only the seal script
uses the private key; the server side only ever reads the public key, and only to verify.
"""

import argparse
import os
from pathlib import Path

from app.config import settings
# SR-13: the same key-pair helper as the SR-02 roll key and the SR-07 delegate keys
from scripts.sign_roll import load_or_create_private_key


def generate_checkpoint_keys(private_path: Path, public_path: Path, force: bool = False) -> tuple[Path, Path]:
    """SR-13: writes a new key pair, private key owner-only (0600) where the OS supports it. Never overwrites unless force."""
    if not force and (private_path.exists() or public_path.exists()):
        raise FileExistsError(private_path)
    private_path.unlink(missing_ok=True)
    public_path.unlink(missing_ok=True)
    # SR-13: on POSIX the files are created owner-only from the first byte, not narrowed afterwards
    previous = os.umask(0o077)
    try:
        load_or_create_private_key(private_path, public_path)
    finally:
        os.umask(previous)
    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o644)  # the public key is not secret
    return private_path, public_path


def main() -> None:
    parser = argparse.ArgumentParser(description="SR-13: create the ballot chain checkpoint signing keys")
    parser.add_argument("--force", action="store_true", help="replace an existing key pair")
    args = parser.parse_args()
    private_path = settings.backend_path(settings.checkpoint_private_key)
    public_path = settings.backend_path(settings.checkpoint_public_key)
    try:
        generate_checkpoint_keys(private_path, public_path, force=args.force)
    except FileExistsError:
        raise SystemExit(
            f"{private_path} or {public_path} already exists. Nothing changed. Replacing the key means "
            "existing checkpoints no longer verify; use --force only if that is what you want."
        )
    print(f"Created {private_path} (private, for python -m scripts.seal_ballots only) and {public_path}.")
    print("Never commit them. keys/ is in .gitignore.")


if __name__ == "__main__":
    main()
