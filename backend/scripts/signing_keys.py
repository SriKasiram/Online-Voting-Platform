"""
SR-02, SR-07, SR-11, SR-13, SR-16, SR-18, SR-20: private keys and signing, for the scripts only.

Creating key files (refusing to overwrite unless forced, private files owner-only), loading Ed25519
private keys, and the one place a private key signs. Nothing under app/ imports this module: the
API only ever reads public keys and verifies (app/key_files.py), as SR-07, SR-13 and SR-18 require.
Each script keeps its own domain tag in the bytes it passes to sign(); SR-18 signs with no tag.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def write_secret_key(path: Path, force: bool = False) -> Path:
    """
    SR-11, SR-20: writes a new AES-256 key (32 random bytes) to path, owner-only (0600) where the
    OS supports it. Never overwrites unless force (raises FileExistsError).
    """
    if path.exists() and not force:
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # SR-11: created owner-only, never readable by others even for a moment
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(AESGCM.generate_key(bit_length=256))
    os.chmod(path, 0o600)  # also when --force replaced an older, wider file
    return path


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """SR-02, SR-13, SR-16, SR-18: an Ed25519 private key from its PEM file, or SystemExit."""
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path} is not an Ed25519 private key")
    return key


def load_or_create_key_pair(private_path: Path, public_path: Path) -> Ed25519PrivateKey:
    """
    SR-02, SR-07: loads the private key, first creating a new development key pair if there is
    none, and writes the matching public key where the verifier reads it.
    """
    if private_path.exists():
        key = load_private_key(private_path)
    else:
        key = Ed25519PrivateKey.generate()
        private_path.parent.mkdir(parents=True, exist_ok=True)
        private_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return key


def write_key_pair(private_path: Path, public_path: Path, force: bool = False) -> tuple[Path, Path]:
    """
    SR-13, SR-18: writes a new key pair, the private key owner-only (0600) where the OS supports it.
    Never overwrites unless force (raises FileExistsError).
    """
    if not force and (private_path.exists() or public_path.exists()):
        raise FileExistsError(private_path)
    private_path.unlink(missing_ok=True)
    public_path.unlink(missing_ok=True)
    # SR-13: on POSIX the files are created owner-only from the first byte, not narrowed afterwards
    previous = os.umask(0o077)
    try:
        load_or_create_key_pair(private_path, public_path)
    finally:
        os.umask(previous)
    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o644)  # the public key is not secret
    return private_path, public_path


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """
    SR-02, SR-07, SR-13, SR-16, SR-18: the one place a private key signs: the raw 64-byte Ed25519
    signature over exactly `message`, which already carries the caller's domain tag (or, for SR-18,
    none). Checked with app.key_files.verify_signature.
    """
    return private_key.sign(message)
