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
import re
import secrets
import unicodedata
import uuid
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

# SR-16: the catalogue and fixed sets the audit writer enforces, and the request being handled
from app import audit_events
from app.config import TOTP_ISSUER, TOTP_VALID_WINDOW, settings
from app.models import Account, AccountRole, AuditLogEntry
from app.request_id import current_request_id

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

# SR-16: 1 = rows written before SR-16 (free-form details); 2 = the allow-listed fields only.
# Old rows are never rewritten, so each row is verified with the formula of its own version.
AUDIT_FORMAT_V1 = 1
AUDIT_FORMAT_V2 = 2
# SR-18: 3 = format 2 plus the release `version` field. New rows are written in this format.
AUDIT_FORMAT_V3 = 3
AUDIT_FORMAT_CURRENT = AUDIT_FORMAT_V3

_UUID_TEXT = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_ACCOUNT_ACTOR = re.compile(rf"account:{_UUID_TEXT}")
_ANY_UUID = re.compile(_UUID_TEXT, re.IGNORECASE)
# SR-16: the shape of a token (base64url, 32+ characters), a token hash (64 hex) or a receipt
# reference (32 hex). Account and request ids are UUIDs, which are taken out before this is applied.
_SECRET_SHAPE = re.compile(r"[0-9a-fA-F]{32}|[A-Za-z0-9_-]{32,}")
_ACCOUNT_ROLES = frozenset(role.value for role in AccountRole)


class AuditFieldError(ValueError):
    """SR-16: the entry would break the audit allow-list, so nothing was written."""


def looks_secret(value: str) -> bool:
    """SR-16: True if the text holds something shaped like a token, a token hash or a receipt."""
    return _SECRET_SHAPE.search(_ANY_UUID.sub("", value)) is not None


def account_actor(account: Account) -> tuple[str, str]:
    """SR-16: the actor and role audit() needs for an account: its id and role, never its username."""
    return f"account:{account.id}", account.role.value


def actor_for(db: Session, account_id: uuid.UUID | None) -> tuple[str, str]:
    """SR-16: the same for an account id, or "unknown" when no account is known."""
    account = db.get(Account, account_id) if account_id else None
    return account_actor(account) if account else (audit_events.UNKNOWN, audit_events.UNKNOWN)


def _checked_fields(
    event_type: str,
    outcome: str,
    actor: str,
    role: str,
    request_id: str,
    batch_no: int | None,
    count: int | None,
    reason: str | None,
    version: int | None = None,
) -> str:
    """SR-16: raises AuditFieldError unless every value is allowed. Returns the event's category."""
    for value in (event_type, outcome, actor, role, request_id, reason):
        if value is not None and (not isinstance(value, str) or looks_secret(value)):
            raise AuditFieldError("an audit value is not plain text or is shaped like a secret")
    category = audit_events.EVENT_CATEGORIES.get(event_type)
    if category is None:
        raise AuditFieldError(f"not a catalogued audit event: {event_type}")
    if outcome not in audit_events.OUTCOMES:
        raise AuditFieldError(f"not an audit outcome: {outcome}")
    if role not in audit_events.ROLES:
        raise AuditFieldError(f"not an audit role: {role}")
    if reason is not None and reason not in audit_events.REASON_CODES:
        raise AuditFieldError("the reason is not a catalogued reason code")
    # SR-16: the actor is an account id, "script" or "unknown", and its role must fit it
    if actor in (audit_events.SCRIPT, audit_events.UNKNOWN):
        if role != actor:
            raise AuditFieldError(f"the {actor} actor must have the {actor} role")
    elif not _ACCOUNT_ACTOR.fullmatch(actor) or role not in _ACCOUNT_ROLES:
        raise AuditFieldError("the actor must be account:<id>, script or unknown, with a matching role")
    if not re.fullmatch(_UUID_TEXT, request_id):
        raise AuditFieldError("the request id must be a lowercase UUID")
    # SR-18: the release version is a whole number too
    for number in (batch_no, count, version):
        if number is not None and (type(number) is not int or number < 0):
            raise AuditFieldError("batch_no, count and version must be whole numbers")
    return category


def _structured_body(entry: AuditLogEntry) -> str:
    # SR-16: every structured field and the format version, in one canonical text form
    # SR-18: format 3 adds `version`; a format 2 row gets exactly the body it was hashed with
    fields = {
        "format_version": entry.format_version,
        # The database may hand the time back in another zone, so use the writer's UTC form
        "created_at": entry.created_at.astimezone(UTC).isoformat(),
        "event_type": entry.event_type,
        "category": entry.category,
        "outcome": entry.outcome,
        "actor": entry.actor,
        "role": entry.role,
        "request_id": str(entry.request_id),
        "batch_no": entry.batch_no,
        "count": entry.count,
        "reason": entry.reason,
    }
    if entry.format_version >= AUDIT_FORMAT_V3:
        fields["version"] = entry.version
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def _v1_body(entry: AuditLogEntry) -> str:
    # SR-01 to SR-15: the formula rows written before SR-16 were hashed with, unchanged
    return json.dumps(
        {
            "created_at": entry.created_at.astimezone(UTC).isoformat(),
            "event_type": entry.event_type,
            "actor": entry.actor,
            "details": entry.details,
        },
        sort_keys=True,
    )


def entry_hash(prev_hash: bytes, entry: AuditLogEntry) -> bytes:
    """The hash an entry must carry, by the formula of its own format version."""
    if entry.format_version == AUDIT_FORMAT_V1:
        body = _v1_body(entry)
    elif entry.format_version in (AUDIT_FORMAT_V2, AUDIT_FORMAT_V3):
        body = _structured_body(entry)
    else:
        # SR-18: a format no writer ever used cannot verify
        return b""
    return hashlib.sha256(prev_hash + body.encode()).digest()


def audit(
    db: Session,
    event_type: str,
    *,
    outcome: str,
    actor: str,
    role: str,
    request_id: str | None = None,
    batch_no: int | None = None,
    count: int | None = None,
    reason: str | None = None,
    version: int | None = None,
    **unexpected: Any,
) -> None:
    """
    Appends an audit entry, chained to the one before it by hash. Committed or
    rolled back with the caller's transaction.

    SR-16: only the allow-listed fields of app/audit_events.py. Anything else (an unknown event
    type or field, a value outside the fixed sets, a non-integer number, anything shaped like a
    token, hash or receipt) raises AuditFieldError before anything is written. The category and
    time are set here, and the request id comes from the request being handled (app/request_id.py).
    Callers write it in the same transaction as the change it describes, so if this fails the
    change is rolled back too.

    SR-18: `version` (a release version) joins the allow-list; the rest is unchanged.
    """
    if unexpected:
        raise AuditFieldError(f"not an allowed audit field: {', '.join(sorted(unexpected))}")
    # SR-16: outside a request (scripts, start-up) each entry gets its own random id
    request_id = request_id or current_request_id() or str(uuid.uuid4())
    category = _checked_fields(event_type, outcome, actor, role, request_id, batch_no, count, reason, version)

    db.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _AUDIT_LOCK_ID})
    prev_hash = db.scalar(select(AuditLogEntry.hash).order_by(AuditLogEntry.id.desc()).limit(1))
    prev_hash = prev_hash or _GENESIS_HASH
    entry = AuditLogEntry(
        created_at=utc_now(),
        event_type=event_type,
        actor=actor,
        category=category,
        outcome=outcome,
        role=role,
        request_id=uuid.UUID(request_id),
        batch_no=batch_no,
        count=count,
        reason=reason,
        version=version,
        # SR-16: the old free-text column is never written again
        details=None,
        format_version=AUDIT_FORMAT_CURRENT,
        prev_hash=prev_hash,
    )
    entry.hash = entry_hash(prev_hash, entry)
    db.add(entry)
    # Written now, so a second entry in the same transaction chains to this one
    db.flush()


def verify_audit_chain(db: Session) -> tuple[int, int | None]:
    """
    SR-05: recomputes the hash chain exactly as audit() builds it. Returns how many
    entries checked out and the id of the first one that does not, or None when the
    whole chain is intact. SR-16: each row by the formula of its format version, and a
    version 2 row must have no free-text details at all.
    """
    prev_hash, checked = _GENESIS_HASH, 0
    # SR-16: populate_existing, so rows this session already holds are re-read from the database:
    # verification must check what is stored now, not what the session saw earlier
    rows = select(AuditLogEntry).order_by(AuditLogEntry.id).execution_options(populate_existing=True)
    for entry in db.scalars(rows):
        stray_details = entry.format_version != AUDIT_FORMAT_V1 and entry.details is not None
        # SR-18: formats 1 and 2 do not hash `version`, so a value there could only have been added later
        stray_version = entry.format_version < AUDIT_FORMAT_V3 and entry.version is not None
        if stray_details or stray_version or entry.prev_hash != prev_hash or entry.hash != entry_hash(prev_hash, entry):
            return checked, entry.id
        prev_hash, checked = entry.hash, checked + 1
    return checked, None


def audit_hash_at(db: Session, position: int) -> bytes | None:
    """SR-16: the hash of the position-th entry (1 = the first) in chain order, or None if there is none."""
    if position < 1:
        return None
    return db.scalar(select(AuditLogEntry.hash).order_by(AuditLogEntry.id).offset(position - 1).limit(1))
