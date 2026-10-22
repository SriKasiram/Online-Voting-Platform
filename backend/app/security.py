"""
Security helpers in one place: tokens and cookies, password hashing, field
encryption, keyed hashes (the roll's blind index and enrolment codes),
authenticator (TOTP) codes, a small rate limiter and the audit log.

Every key is derived from SECRET_KEY with HKDF, so one setting configures them
all and a key made for one purpose is never used for another.
"""

import hashlib
import hmac
import json
import secrets
import unicodedata
from collections import deque
from datetime import UTC, date, datetime
from threading import Lock
from time import monotonic
from typing import Any

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import Response
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import TOTP_ISSUER, TOTP_VALID_WINDOW, settings
from app.models import AuditLogEntry

# ---------------------------------------------------------------
# Tokens and cookies
# ---------------------------------------------------------------

# SR-01: one cookie for both sign-in stages. The server records which stage each session is at.
SESSION_COOKIE = "session"
SESSION_PATH = "/"
REGISTRATION_COOKIE = "registration_session"
REGISTRATION_PATH = "/api/register"


def utc_now() -> datetime:
    # SR-01: the one clock for lockouts, session expiry and code checks, so tests can replace it
    return datetime.now(UTC)


def new_token() -> str:
    """A random, unguessable value for a cookie or a ballot token."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> bytes:
    """What the database stores for a token, so a copy of the table cannot be replayed."""
    return hashlib.sha256(token.encode()).digest()


# SR-01: `secure` added for the session cookie (COOKIE_SECURE). The registration cookie is unchanged.
def set_cookie(
    response: Response, name: str, value: str, path: str, max_age: int | None = None, secure: bool = False
) -> None:
    # HttpOnly keeps the token away from page scripts. SameSite=Strict stops other sites sending it.
    response.set_cookie(name, value, path=path, max_age=max_age, httponly=True, samesite="strict", secure=secure)


def clear_cookie(response: Response, name: str, path: str, secure: bool = False) -> None:
    response.delete_cookie(name, path=path, httponly=True, samesite="strict", secure=secure)


# ---------------------------------------------------------------
# Keys
# ---------------------------------------------------------------


def _derive_key(purpose: str) -> bytes:
    secret = settings.secret_key.get_secret_value().encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=purpose.encode()).derive(secret)


_FIELD_KEY = _derive_key("field-encryption-v1")
_INDEX_KEY = _derive_key("roll-blind-index-v1")
_CODE_KEY = _derive_key("enrolment-code-v1")

# ---------------------------------------------------------------
# Passwords (Argon2id)
# ---------------------------------------------------------------

# SR-01: argon2-cffi's defaults are Argon2id, so every hash starts with "$argon2id$"
_hasher = PasswordHasher()
# Checked when there is no account, so an unknown username takes as long as a wrong password
# SR-01: also checked for a locked account, so a locked account answers as slowly as any other
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        _hasher.verify(password_hash or _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return False
    return password_hash is not None


# ---------------------------------------------------------------
# Field encryption (AES-256-GCM)
# ---------------------------------------------------------------


def encrypt(value: str, field: str) -> bytes:
    """
    Encrypts a personal or secret value. `field` names the column, such as
    "electoral_roll.full_name", and is bound to the ciphertext, so a value
    copied into another column will not decrypt.
    """
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(_FIELD_KEY).encrypt(nonce, value.encode(), field.encode())


def decrypt(blob: bytes, field: str) -> str:
    return AESGCM(_FIELD_KEY).decrypt(blob[:12], blob[12:], field.encode()).decode()


def decrypt_or_none(blob: bytes | None, field: str) -> str | None:
    """For rows written before encryption existed, which hold plain values."""
    if blob is None:
        return None
    try:
        return decrypt(blob, field)
    except (InvalidTag, ValueError):
        return None


# ---------------------------------------------------------------
# Keyed hashes: the roll's blind index and enrolment codes
# ---------------------------------------------------------------


def _keyed_hash(key: bytes, value: str) -> bytes:
    return hmac.new(key, value.encode(), hashlib.sha256).digest()


def normalise_name(value: str) -> str:
    """Trims, lowercases, collapses spaces and strips accents: "  José  Smith" becomes "jose smith"."""
    decomposed = unicodedata.normalize("NFKD", value)
    without_accents = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return " ".join(without_accents.casefold().split())


def normalise_date(value: str) -> str:
    """YYYY-MM-DD, or an empty string when the value is not a real date."""
    try:
        return date.fromisoformat(value.strip()).isoformat()
    except ValueError:
        return ""


def roll_lookup(given_name: str, surname: str, date_of_birth: str, postcode: str) -> bytes:
    """Blind index of a roll entry, so an entry can be found without decrypting anything."""
    parts = (
        normalise_name(given_name),
        normalise_name(surname),
        normalise_date(date_of_birth),
        "".join(postcode.split()),
    )
    return _keyed_hash(_INDEX_KEY, "|".join(parts))


def enrolment_code_hash(code: str) -> bytes:
    """Keyed hash of an enrolment code. Ignores case, spaces and hyphens."""
    return _keyed_hash(_CODE_KEY, "".join(ch for ch in code.upper() if ch.isalnum()))


def same(a: bytes, b: bytes) -> bool:
    """Constant-time comparison, so the time taken reveals nothing about either value."""
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------
# Authenticator app codes (TOTP)
# ---------------------------------------------------------------


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    """The otpauth:// link an authenticator app reads from the QR code."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=TOTP_ISSUER)


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=TOTP_VALID_WINDOW)


def totp_matching_step(secret: str, code: str, now: datetime) -> int | None:
    """
    SR-01: the 30-second time step, one either side of `now`, whose code matches,
    or None. Every step is compared in constant time. Sign in stores the step so
    the same code cannot be used twice.
    """
    totp = pyotp.TOTP(secret)
    current = totp.timecode(now)
    matched = None
    for step in range(current - TOTP_VALID_WINDOW, current + TOTP_VALID_WINDOW + 1):
        if same(totp.generate_otp(step).encode(), code.encode()):
            matched = step
    return matched


# ---------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------


class RateLimiter:
    """
    Allows `limit` hits per key in a sliding window. Kept in memory, which is
    enough for one server process; several processes would need a shared store.
    """

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str, limit: int, window_seconds: float) -> bool:
        now = monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= now - window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


rate_limiter = RateLimiter()

# ---------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------

_GENESIS_HASH = bytes(32)
# Any fixed number. Holding this lock while appending stops two writers forking the chain.
_AUDIT_LOCK_ID = 51_204


def audit(db: Session, event_type: str, actor: str, **details: Any) -> None:
    """
    Appends an audit entry, chained to the one before it by hash. Committed or
    rolled back with the caller's transaction. Never pass personal data, codes
    or secrets: `actor` is a roll entry id ("roll:<id>"), a client IP or "unknown".
    """
    db.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _AUDIT_LOCK_ID})
    prev_hash = db.scalar(select(AuditLogEntry.hash).order_by(AuditLogEntry.id.desc()).limit(1))
    prev_hash = prev_hash or _GENESIS_HASH
    created_at = utc_now()
    body = json.dumps(
        {"created_at": created_at.isoformat(), "event_type": event_type, "actor": actor, "details": details},
        sort_keys=True,
    )
    db.add(
        AuditLogEntry(
            created_at=created_at,
            event_type=event_type,
            actor=actor,
            details=details,
            prev_hash=prev_hash,
            hash=hashlib.sha256(prev_hash + body.encode()).digest(),
        )
    )
    # Written now, so a second entry in the same transaction chains to this one
    db.flush()


def verify_audit_chain(db: Session) -> tuple[int, int | None]:
    """
    SR-05: recomputes the hash chain exactly as audit() builds it (audit() is
    unchanged). Returns how many entries checked out and the id of the first one
    that does not, or None when the whole chain is intact.
    """
    prev_hash, checked = _GENESIS_HASH, 0
    for entry in db.scalars(select(AuditLogEntry).order_by(AuditLogEntry.id)):
        body = json.dumps(
            {
                # The database may hand the time back in another zone, so restore audit()'s UTC form
                "created_at": entry.created_at.astimezone(UTC).isoformat(),
                "event_type": entry.event_type,
                "actor": entry.actor,
                "details": entry.details,
            },
            sort_keys=True,
        )
        if entry.prev_hash != prev_hash or entry.hash != hashlib.sha256(prev_hash + body.encode()).digest():
            return checked, entry.id
        prev_hash, checked = entry.hash, checked + 1
    return checked, None
