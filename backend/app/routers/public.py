"""
SR-18: public routes, open without a session. The only one is the published results key, so a
recipient of a released House result can check its signature and the key's fingerprint.

In the prototype this route stands in for the "official page". It is served over TLS 1.3 only
(SR-10), with no-store and HSTS like every response. No route serves a result dataset: results
leave the platform only through python -m scripts.release_results.
"""

import logging

from fastapi import APIRouter, HTTPException, status
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.config import settings
from app.result_dataset import key_fingerprint, load_results_public_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/public", tags=["public"])


@router.get("/results-key")
def results_key() -> dict[str, str]:
    """SR-18: the Ed25519 public key that signs released House results, and its fingerprint."""
    path = settings.backend_path(settings.results_public_key)
    try:
        key = load_results_public_key(path)
    except (OSError, ValueError):
        # SR-18: not configured yet (no key generated), or not an Ed25519 key: nothing to publish
        if path.exists():
            logger.error("The results public key at %s is not a valid Ed25519 key", path.name)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_configured") from None
    return {
        "algorithm": "Ed25519",
        "public_key_pem": key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
        "fingerprint_sha256": key_fingerprint(key),
    }
