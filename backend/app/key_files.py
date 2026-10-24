"""
SR-02, SR-07, SR-11, SR-13, SR-16, SR-18, SR-20: reading key files, and the one Ed25519 signature check.

Two kinds of key are read here: 32-byte AES-256 keys (the SR-11 ballot key and the SR-20 backup key)
and Ed25519 public keys (the SR-02 roll key, the SR-07 delegate keyring, the SR-13 and SR-16
checkpoint key, and the SR-18 results key). No private key is ever read here: private keys and
signing live in scripts/signing_keys.py, which nothing under app/ imports (SR-07, SR-13, SR-18).
"""

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# SR-11, SR-20: AES-256
KEY_BYTES = 32


class KeyFileProblem(Exception):
    """
    SR-11, SR-20: why a symmetric key file cannot be used: "missing", "readable_by_others" or
    "wrong_size" (then `size` is the number of bytes found). Each caller turns it into its own error
    and message, so what a user sees is unchanged.
    """

    def __init__(self, reason: str, size: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.size = size


def readable_by_others(path: Path) -> bool:
    # SR-11, SR-20: on POSIX a key must give no access to group or others. Windows has no such mode
    # bits, so the check is skipped there.
    return os.name == "posix" and bool(Path(path).stat().st_mode & 0o077)


def read_symmetric_key(path: Path, *, size_first: bool = False) -> bytes:
    """
    SR-11, SR-20: a 32-byte AES-256 key, failing closed: the file must exist, hold exactly 32 bytes
    and, on POSIX, be owner-only. The SR-11 ballot key checks the permissions before the size and
    the SR-20 backup key the size first; `size_first` keeps each order, and so each message, as it was.
    """
    path = Path(path)
    if not path.is_file():
        raise KeyFileProblem("missing")
    if not size_first and readable_by_others(path):
        raise KeyFileProblem("readable_by_others")
    key = path.read_bytes()
    if len(key) != KEY_BYTES:
        raise KeyFileProblem("wrong_size", len(key))
    if size_first and readable_by_others(path):
        raise KeyFileProblem("readable_by_others")
    return key


def parse_public_key(pem: bytes) -> Ed25519PublicKey:
    # SR-02, SR-07, SR-13, SR-16, SR-18: an Ed25519 public key from its PEM text, or ValueError.
    # SR-07: split out of the SR-02 roll key loader so the ballot definition keyring uses it too.
    key = load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def load_public_key_file(path: Path) -> Ed25519PublicKey:
    # SR-02, SR-13, SR-16, SR-18: a public key file. OSError if it is missing, ValueError if it is not Ed25519.
    return parse_public_key(Path(path).read_bytes())


def verify_signature(key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    # SR-02, SR-07, SR-13, SR-16, SR-18: the one Ed25519 check, for roll records, ballot definitions,
    # chain and audit checkpoints, and result releases. Never raises.
    try:
        key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
