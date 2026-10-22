"""
SR-10: creates the one development TLS certificate and its key. It is self-signed, for localhost
and 127.0.0.1, ECDSA P-256 signed with SHA-256, and valid for 365 days. Run inside backend/:

    python -m scripts.dev_certs            # writes certs/dev-cert.pem and certs/dev-key.pem
    python -m scripts.dev_certs --force    # replaces them

certs/ is in .gitignore: the key belongs to this computer only and is never committed.
"""

import argparse
import ipaddress
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# SR-10: certs/ at the project root, where TLS_CERT_FILE and TLS_KEY_FILE point by default.
# Worked out here rather than imported from app.config, so no database settings are needed.
CERTS_DIR = Path(__file__).resolve().parents[2] / "certs"
CERT_NAME, KEY_NAME = "dev-cert.pem", "dev-key.pem"
VALID_DAYS = 365

TRUST_INSTRUCTIONS = r"""
Trust the certificate once, so the browser accepts https://localhost:8443 (commands run from the project root):
  Windows:  certutil -user -addstore Root certs\dev-cert.pem    (confirm the prompt, then restart the browser)
  macOS:    security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db certs/dev-cert.pem
  Linux:    certutil -d sql:$HOME/.pki/nssdb -A -t "P,," -n evoting-dev -i certs/dev-cert.pem    (Chrome, libnss3-tools)
            sudo cp certs/dev-cert.pem /usr/local/share/ca-certificates/evoting-dev.crt && sudo update-ca-certificates
Vite dev server only (inside frontend/), so its proxy can check the backend's certificate:
  macOS/Linux:  NODE_EXTRA_CA_CERTS=../certs/dev-cert.pem npm run dev
  PowerShell:   $env:NODE_EXTRA_CA_CERTS = "..\certs\dev-cert.pem"; npm run dev
"""


def generate_dev_cert(out_dir: Path, force: bool = False) -> tuple[Path, Path]:
    """
    SR-10: writes dev-cert.pem and dev-key.pem into out_dir and returns their paths. Existing
    files are never replaced unless force is set. Tests call this with a temporary folder.
    """
    cert_path, key_path = out_dir / CERT_NAME, out_dir / KEY_NAME
    if not force and (cert_path.exists() or key_path.exists()):
        raise FileExistsError(f"{cert_path} or {key_path} already exists")

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "evoting-prototype development"),
        ]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=VALID_DAYS))
        # SR-10: clients check the name they connected to against these, never the common name
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        # SR-10: a server certificate, not a CA, so trusting it vouches for this server and nothing else
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    # SR-10: the key is created owner-only (0600) where the OS supports it, never readable first
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(key_bytes)
    os.chmod(key_path, 0o600)  # also when --force replaced an older, wider file
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def main() -> None:
    parser = argparse.ArgumentParser(description="SR-10: create the development TLS certificate and key")
    parser.add_argument("--force", action="store_true", help="replace an existing certificate and key")
    args = parser.parse_args()
    try:
        cert_path, key_path = generate_dev_cert(CERTS_DIR, force=args.force)
    except FileExistsError:
        raise SystemExit(f"{CERTS_DIR} already holds a certificate or key. Nothing changed. Use --force to replace them.")
    print(f"Created {cert_path} and {key_path} (localhost and 127.0.0.1, valid {VALID_DAYS} days).")
    print(TRUST_INSTRUCTIONS)


if __name__ == "__main__":
    main()
