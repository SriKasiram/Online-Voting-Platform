"""
Registration, in three steps, for people already on the electoral roll.

1. verify:  given name, surname, date of birth, postcode and the one-time
            enrolment code. Every failure gets the same answer, so this step
            never reveals whether someone is on the roll.
2. account: username and password. Returns the authenticator secret, once.
3. confirm: a code from the authenticator app proves it is set up. Only then
            is the account created.

The steps share a registration session held on the server and named by an
HttpOnly cookie that lasts REGISTRATION_SESSION_MINUTES. Steps cannot be
skipped or repeated: each one needs the session at the stage it expects.
"""

import re
import uuid
from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import config
# SR-16: registration events have no account yet ("unknown"), until the account is created
from app.audit_events import FAILURE, SUCCESS, UNKNOWN
from app.deps import DbSession
from app.models import Account, AccountRole, ElectoralRollEntry, RegistrationSession, RegistrationStage
from app.schemas import RegisterAccountIn, RegisterAccountOut, RegisterConfirmIn, RegisterVerifyIn
from app.security import (
    REGISTRATION_COOKIE,
    REGISTRATION_PATH,
    account_actor,
    audit,
    clear_cookie,
    decrypt,
    encrypt,
    enrolment_code_hash,
    hash_password,
    hash_token,
    new_token,
    new_totp_secret,
    rate_limiter,
    roll_lookup,
    same,
    set_cookie,
    totp_uri,
    utc_now,
    verify_totp,
)

router = APIRouter(prefix="/register", tags=["register"])

# Compared against when no roll entry matches, so a miss does the same work as a wrong code
_DUMMY_CODE_HASH = enrolment_code_hash(new_token())


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def delete_expired(db: Session) -> None:
    """Housekeeping on every request, committed on its own so a failed request still does it."""
    db.execute(delete(RegistrationSession).where(RegistrationSession.expires_at <= utc_now()))
    db.commit()


def current_registration(request: Request, db: Session, stage: RegistrationStage) -> RegistrationSession:
    token = request.cookies.get(REGISTRATION_COOKIE)
    registration = db.get(RegistrationSession, hash_token(token)) if token else None
    if registration is None or registration.stage != stage or registration.expires_at <= utc_now():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "registration_session_invalid")
    return registration


def end_registration(db: Session, registration: RegistrationSession, reason: str) -> None:
    db.delete(registration)
    # SR-16: "unknown": no account exists yet, and a roll entry id is not an allowed actor
    audit(db, "REGISTRATION_FAILED", outcome=FAILURE, actor=UNKNOWN, role=UNKNOWN, reason=reason)
    db.commit()


@router.post("/verify", status_code=status.HTTP_204_NO_CONTENT)
def verify(body: RegisterVerifyIn, request: Request, response: Response, db: DbSession) -> None:
    """Step 1. Finds the roll entry by its blind index and spends the enrolment code."""
    delete_expired(db)
    ip = client_ip(request)
    now = utc_now()

    lookup = roll_lookup(body.given_name, body.surname, body.date_of_birth, body.postcode)
    # Locking the row stops two simultaneous attempts from both spending the code
    entry = db.scalar(
        select(ElectoralRollEntry).where(ElectoralRollEntry.roll_lookup == lookup).with_for_update()
    )
    stored_hash = entry.enrolment_code_hash if entry is not None else None
    code_matches = same(enrolment_code_hash(body.enrolment_code), stored_hash or _DUMMY_CODE_HASH)
    code_matches = code_matches and stored_hash is not None

    # SR-01: window constant renamed only; registration limits are unchanged
    allowed = rate_limiter.allow(
        f"register-ip:{ip}", config.REGISTER_VERIFY_LIMIT_PER_IP, config.REGISTER_VERIFY_WINDOW_SECONDS
    )
    if allowed and entry is not None:
        allowed = rate_limiter.allow(
            f"register-roll:{entry.id}", config.REGISTER_VERIFY_LIMIT_PER_ENTRY, config.REGISTER_VERIFY_WINDOW_SECONDS
        )

    if not (
        allowed
        and entry is not None
        and entry.enrolled
        and entry.registered_at is None
        and code_matches
        and entry.code_expires_at is not None
        and entry.code_expires_at > now
        and entry.code_attempts < config.ENROLMENT_CODE_MAX_ATTEMPTS
    ):
        if allowed and entry is not None and stored_hash is not None and not code_matches:
            # Counts toward locking this entry's code
            entry.code_attempts += 1
        # SR-16: never the client IP: an IP address is not an allowed audit value
        audit(db, "REGISTRATION_FAILED", outcome=FAILURE, actor=UNKNOWN, role=UNKNOWN, reason="details_not_verified")
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "registration_failed")

    # Single use: the code is spent now, even if the later steps are never finished
    entry.enrolment_code_hash = None
    entry.code_expires_at = None
    token = new_token()
    db.add(
        RegistrationSession(
            id_hash=hash_token(token),
            roll_id=entry.id,
            stage=RegistrationStage.VERIFIED,
            expires_at=now + timedelta(minutes=config.REGISTRATION_SESSION_MINUTES),
        )
    )
    audit(db, "REGISTRATION_STARTED", outcome=SUCCESS, actor=UNKNOWN, role=UNKNOWN)
    db.commit()
    set_cookie(
        response, REGISTRATION_COOKIE, token, REGISTRATION_PATH, max_age=config.REGISTRATION_SESSION_MINUTES * 60
    )


@router.post("/account")
def account(body: RegisterAccountIn, request: Request, response: Response, db: DbSession) -> RegisterAccountOut:
    """Step 2. Holds the new account in the registration session, not in accounts yet."""
    delete_expired(db)
    registration = current_registration(request, db, RegistrationStage.VERIFIED)

    username = body.username.strip()
    if not re.fullmatch(config.USERNAME_PATTERN, username):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "username_invalid")
    if len(body.password) < config.PASSWORD_MIN_LENGTH:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "password_too_short")
    if body.password.casefold() == username.casefold():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "password_is_username")
    # Both columns are citext, so this comparison ignores letter case
    in_use = db.scalar(select(Account.id).where(Account.username == username)) or db.scalar(
        select(RegistrationSession.id_hash).where(
            RegistrationSession.username == username, RegistrationSession.id_hash != registration.id_hash
        )
    )
    if in_use:
        raise HTTPException(status.HTTP_409_CONFLICT, "username_taken")

    secret = new_totp_secret()
    registration.username = username
    registration.password_hash = hash_password(body.password)
    registration.totp_secret_enc = encrypt(secret, "registration_sessions.totp_secret")
    registration.stage = RegistrationStage.ACCOUNT_PENDING
    db.commit()

    # Shown once: no browser or proxy may keep a copy
    response.headers["Cache-Control"] = "no-store"
    return RegisterAccountOut(otpauth_uri=totp_uri(secret, username), secret=secret)


@router.post("/confirm", status_code=status.HTTP_204_NO_CONTENT)
def confirm(body: RegisterConfirmIn, request: Request, response: Response, db: DbSession) -> None:
    """Step 3. Creates the account once a code from the authenticator app checks out."""
    delete_expired(db)
    registration = current_registration(request, db, RegistrationStage.ACCOUNT_PENDING)
    id_hash, roll_id = registration.id_hash, registration.roll_id
    secret = decrypt(registration.totp_secret_enc or b"", "registration_sessions.totp_secret")

    if not verify_totp(secret, body.otp_code):
        registration.attempts += 1
        if registration.attempts >= config.REGISTRATION_CODE_MAX_ATTEMPTS:
            end_registration(db, registration, "too_many_attempts")
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "too_many_attempts")
        audit(db, "REGISTRATION_FAILED", outcome=FAILURE, actor=UNKNOWN, role=UNKNOWN, reason="wrong_code")
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "wrong_code")

    # One transaction: mark the roll entry, create the account, end the registration.
    # Only one registration can set registered_at, and UNIQUE(accounts.roll_id) backs that up.
    marked = db.execute(
        update(ElectoralRollEntry)
        .where(ElectoralRollEntry.id == roll_id, ElectoralRollEntry.registered_at.is_(None))
        .values(registered_at=utc_now())
        .returning(ElectoralRollEntry.id)
        .execution_options(synchronize_session=False)
    ).first()
    if marked is None:
        db.rollback()
        end_registration(db, db.get_one(RegistrationSession, id_hash), "already_registered")
        raise HTTPException(status.HTTP_409_CONFLICT, "already_registered")

    # SR-16: the id is chosen here, so the completion entry can name the new account
    account = Account(
        id=uuid.uuid4(),
        username=registration.username,
        password_hash=registration.password_hash,
        role=AccountRole.ELECTOR,  # SR-05: the role member was renamed; registration only ever makes electors
        roll_id=roll_id,
        totp_secret_enc=encrypt(secret, "accounts.totp_secret"),
    )
    db.add(account)
    db.delete(registration)
    actor, role = account_actor(account)
    try:
        # SR-16: inside the try, because writing the entry flushes the account insert, and a
        # username taken meanwhile must get the same answer as at the commit
        audit(db, "REGISTRATION_COMPLETED", outcome=SUCCESS, actor=actor, role=role)
        db.commit()
    except IntegrityError as error:
        db.rollback()
        registration = db.get_one(RegistrationSession, id_hash)
        if getattr(getattr(error.orig, "diag", None), "constraint_name", None) == "uq_accounts_username":
            # Someone else finished with this username first: back to step 2 to choose another
            registration.stage = RegistrationStage.VERIFIED
            registration.username = registration.password_hash = registration.totp_secret_enc = None
            registration.attempts = 0
            db.commit()
            raise HTTPException(status.HTTP_409_CONFLICT, "username_taken") from None
        end_registration(db, registration, "already_registered")
        raise HTTPException(status.HTTP_409_CONFLICT, "already_registered") from None

    clear_cookie(response, REGISTRATION_COOKIE, REGISTRATION_PATH)
