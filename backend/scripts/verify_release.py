"""
SR-18: the recipient's check of a released House result. Self-contained on purpose: it uses only
the Python standard library and the cryptography package, never the platform's own code, database
or settings, so anyone receiving a release can run it on their own machine:

    python verify_release.py --dataset result.json --signature result.json.sig \
        --public-key results_public.pem [--expected-fingerprint HEX]

Get results_public.pem, and the fingerprint to expect, from the official page (in the prototype,
https://localhost:8443/api/public/results-key), never from the release folder.

Checks: the signature verifies over the exact bytes of the file; the dataset names this same key
(signing_key_fingerprint); and, if given, the key's fingerprint is the one expected. Prints VALID
with the election, release version and final chain head, or INVALID with the reason. Exit code 0
or 1.

The OpenSSL 3.0 (or later) equivalent of the signature check:

    openssl pkeyutl -verify -pubin -inkey results_public.pem -rawin -in result.json -sigfile result.json.sig
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

SCHEMA = "evoting-house-result-v1"


def fingerprint(key: Ed25519PublicKey) -> str:
    # SR-18: SHA-256, as lowercase hex, of the raw 32-byte public key (the platform's definition)
    return hashlib.sha256(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()


def check(dataset_path: Path, signature_path: Path, key_path: Path, expected: str | None) -> tuple[bool, str]:
    """SR-18: (valid, what to print). Never raises for a bad input: every problem is a reason."""
    try:
        key = load_pem_public_key(key_path.read_bytes())
    except (OSError, ValueError) as problem:
        return False, f"the public key cannot be read ({problem})"
    if not isinstance(key, Ed25519PublicKey):
        return False, "the public key is not an Ed25519 key"
    if expected is not None and fingerprint(key) != expected.strip().lower():
        return False, "the public key's fingerprint is not the expected one"
    try:
        data, signature = dataset_path.read_bytes(), signature_path.read_bytes()
    except OSError as problem:
        return False, f"a file cannot be read ({problem})"
    # SR-18: over the exact bytes received, so not even a changed space or line ending passes
    try:
        key.verify(signature, data)
    except InvalidSignature:
        return False, "the signature does not match this dataset and key"
    try:
        dataset = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False, "the dataset is not UTF-8 JSON"
    if not isinstance(dataset, dict) or dataset.get("schema") != SCHEMA:
        return False, f"the dataset is not an {SCHEMA} dataset"
    if dataset.get("signing_key_fingerprint") != fingerprint(key):
        return False, "the dataset names a different signing key"
    return True, (
        f"election {dataset.get('election_id')}, release version {dataset.get('release_version')}, "
        f"final chain head {dataset.get('final_chain_head')}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-18: verify a released House result")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--expected-fingerprint", help="the fingerprint published on the official page")
    args = parser.parse_args(argv)
    valid, message = check(args.dataset, args.signature, args.public_key, args.expected_fingerprint)
    print(f"VALID: {message}" if valid else f"INVALID: {message}")
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
