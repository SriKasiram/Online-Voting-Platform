"""
SR-10: the way to run the app. The API and the built frontend share one HTTPS port, TLS 1.3 only,
with no plaintext listener and no fallback. Run inside backend/ with the virtual environment active:

    python -m app.serve

TLS 1.3 is the only protocol the system security specification approves for this prototype.
"""

import ssl
import sys
from pathlib import Path

import uvicorn

from app.config import settings
from app.main import app

# SR-10: this computer only. The certificate names localhost and 127.0.0.1.
HOST = "127.0.0.1"


def tls_config(certfile: Path, keyfile: Path, port: int) -> uvicorn.Config:
    """SR-10: the server's settings, with an SSL context that accepts TLS 1.3 and nothing older."""
    config = uvicorn.Config(
        app,
        host=HOST,
        port=port,
        ssl_certfile=str(certfile),
        ssl_keyfile=str(keyfile),
        # SR-10: uvicorn ends TLS itself, so no client may claim another scheme or address through
        # X-Forwarded-* headers, which uvicorn would otherwise trust from 127.0.0.1
        proxy_headers=False,
    )
    config.load()
    if config.ssl is None:
        raise RuntimeError("TLS was not configured")
    # SR-10: uvicorn has no minimum-version option, so it is set on the context it has just built
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    return config


def main() -> None:
    certfile = settings.tls_path(settings.tls_cert_file)
    keyfile = settings.tls_path(settings.tls_key_file)
    missing = [str(path) for path in (certfile, keyfile) if not path.is_file()]
    if missing:
        # SR-10: no certificate means no server, never a plaintext or weaker fallback
        sys.exit(
            "Refusing to start: TLS certificate or key not found:\n  "
            + "\n  ".join(missing)
            + "\nCreate them inside backend/ with:  python -m scripts.dev_certs"
        )
    config = tls_config(certfile, keyfile, settings.server_port)
    print(f"Serving the API and the built frontend at https://localhost:{config.port} (TLS 1.3 only)")
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
