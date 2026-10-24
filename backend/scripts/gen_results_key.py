"""
SR-18: creates the Ed25519 key pair that signs released House results. Run inside backend/:

    python -m scripts.gen_results_key            # keys/results_private.pem and keys/results_public.pem
    python -m scripts.gen_results_key --force    # replaces them

A key of its own, never the SR-07 delegate keys or the SR-13 checkpoint key: because it signs
nothing but result datasets, the signed bytes carry no domain tag and a recipient can verify them
with standard tools (scripts/verify_release.py or OpenSSL 3). Only scripts/release_results.py uses
the private key; the API serves the public key at /api/public/results-key.

DEVELOPMENT KEYS ONLY: keys/ is in .gitignore. In a real deployment this key would be held offline
or in an HSM (design only).
"""

import argparse
from pathlib import Path

from app.config import settings
from app.result_dataset import key_fingerprint, load_results_public_key
# SR-18: the same key-pair writer as the SR-13 checkpoint key (private key 0600 where supported)
from scripts.signing_keys import write_key_pair


def generate_results_keys(private_path: Path, public_path: Path, force: bool = False) -> tuple[Path, Path]:
    """SR-18: a new results key pair. Never overwrites unless force (raises FileExistsError)."""
    return write_key_pair(private_path, public_path, force=force)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-18: create the House results signing keys")
    parser.add_argument("--force", action="store_true", help="replace an existing key pair")
    args = parser.parse_args(argv)
    private_path = settings.backend_path(settings.results_private_key)
    public_path = settings.backend_path(settings.results_public_key)
    try:
        generate_results_keys(private_path, public_path, force=args.force)
    except FileExistsError:
        print(
            f"{private_path} or {public_path} already exists. Nothing changed. Replacing the key means "
            "earlier releases no longer verify against the published key; use --force only if that is what you want."
        )
        return 1
    print(f"Created {private_path} (private, for python -m scripts.release_results only) and {public_path}.")
    # SR-18: printed so the operator can publish it alongside the key (it is the key's own hash, not a secret)
    print(f"Fingerprint (SHA-256 of the raw public key): {key_fingerprint(load_results_public_key(public_path))}")
    print("Never commit them. keys/ is in .gitignore.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
