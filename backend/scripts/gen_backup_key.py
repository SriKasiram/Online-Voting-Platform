"""
SR-20: creates the AES-256 key that encrypts database backups. Run inside backend/:

    python -m scripts.gen_backup_key            # keys/backup.key
    python -m scripts.gen_backup_key --force    # replaces it

A key of its own, never the SR-11 ballot key: anyone holding a backup still needs this key, and
losing one key does not expose what the other protects. Keep a copy apart from the backups (a
backup is useless without its key) and never commit it: keys/ is in .gitignore.
"""

import argparse
from pathlib import Path

from app.config import settings
# SR-20: the same 32-random-byte, owner-only (0600) writer as the SR-11 ballot key, for a separate file
from scripts.gen_ballot_key import generate_ballot_key


def generate_backup_key(path: Path, force: bool = False) -> Path:
    """SR-20: a new backup key. Never overwrites unless force (raises FileExistsError)."""
    return generate_ballot_key(path, force=force)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-20: create the AES-256 backup encryption key")
    parser.add_argument("--force", action="store_true", help="replace an existing key")
    args = parser.parse_args(argv)
    path = settings.backend_path(settings.backup_key_file)
    try:
        generate_backup_key(path, force=args.force)
    except FileExistsError:
        print(f"{path} already exists. Nothing changed. Replacing it makes every existing backup unreadable; use --force only if that is what you want.")
        return 1
    print(f"Created {path} (32 random bytes). Keep a copy apart from the backups, and never commit it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
