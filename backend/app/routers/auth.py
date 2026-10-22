"""
Sign in, in two parts (password, then a code from the voter's authenticator
app), then extend or end the session.

SR-01: no voting route opens until both parts pass. Every failure gets the same
401, failures at either part count toward locking the account, and each client
IP has a limit on sign-in requests.
"""

from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import case, delete, or_, select, update
from sqlalchemy.orm import Session

from app.config import settings
from app.deps import DbSession
from app.models import Account, AccountRole, AuthSession, ElectoralRollEntry, SessionStage
from app.schemas import LoginIn, VerifyIn, VerifyOut
from app.security import (
    SESSION_COOKIE,
    SESSION_PATH,
    audit,
    clear_cookie,
    decrypt_or_none,
    hash_token,
    new_token,
    rate_limiter,
    set_cookie,
    totp_matching_step,
    utc_now,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def display_name(db: Session, account: Account) -> str:
    # SR-05: staff have no roll entry, so they see their username. Electors are unchanged.
    if account.role != AccountRole.ELECTOR:
        return account.username
    roll = db.get(ElectoralRollEntry, account.roll_id) if account.roll_id else None
    name = decrypt_or_none(roll.full_name_enc, "electoral_roll.full_name") if roll else None
    return name or account.username


def rejected() -> HTTPException:
    # SR-01: the one answer for a wrong password, unknown user, wrong code or locked account
    return HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_credentials")


def log(db: Session, event_type: str, account_id: UUID | None, **details: str) -> None:
    # SR-01: an audit entry names the account (or "unknown") and the event, never anything typed
    # SR-04: `details` added for a short reason code
    audit(db, event_type, actor=f"account:{account_id}" if account_id else "unknown", **details)


def check_ip_limit(request: Request, db: Session) -> None:
    # SR-01: limits sign-in requests per client IP. Uses the connecting address,
    # never X-Forwarded-For, which any client can set.
    ip = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(f"auth-ip:{ip}", settings.rate_limit_attempts, settings.rate_limit_window_seconds):
        log(db, "auth_rate_limited", None)
        db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too_many_requests")


def record_failure(db: Session, account_id: UUID, event_type: str) -> None:
    """
    SR-01: counts a failed attempt in one UPDATE, so parallel attempts cannot
    lose a count. A lock that has run out starts the count again, and reaching
    MAX_FAILED_ATTEMPTS locks the account for LOCK_MINUTES.
    """
    now = utc_now()
    lock_ended = Account.locked_until <= now
    count = case((lock_ended, 1), else_=Account.failed_logins + 1)
    locked_until = db.execute(
        update(Account)
        # An account locked right now is not counted again, so its lock never grows
        .where(Account.id == account_id, or_(Account.locked_until.is_(None), lock_ended))
        .values(
            failed_logins=count,
            locked_until=case(
                (count >= settings.max_failed_attempts, now + timedelta(minutes=settings.lock_minutes)),
                else_=None,
            ),
        )
        .returning(Account.locked_until)
        .execution_options(synchronize_session=False)
    ).scalar()
    log(db, event_type, account_id)
    if locked_until is not None:
        # A sign in waiting for its code cannot finish once the account is locked
        db.execute(
            delete(AuthSession).where(
                AuthSession.account_id == account_id, AuthSession.stage == SessionStage.MFA_PENDING
            )
        )
        log(db, "auth_account_locked", account_id)
    db.commit()


def start_session(db: Session, response: Response, account_id: UUID, stage: SessionStage, minutes: int) -> None:
    # SR-01: a new random token for each stage, stored only as its SHA-256. The cookie has
    # no Max-Age: expires_at on the server decides when the session ends.
    token = new_token()
    db.add(
        AuthSession(
            session_id_hash=hash_token(token),
            account_id=account_id,
            stage=stage,
            expires_at=utc_now() + timedelta(minutes=minutes),
        )
    )
    db.commit()
    set_cookie(response, SESSION_COOKIE, token, SESSION_PATH, secure=settings.cookie_secure)


@router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
def login(body: LoginIn, request: Request, response: Response, db: DbSession) -> None:
    """Part 1. SR-01: checks the password against its Argon2id hash, then waits for the code."""
    check_ip_limit(request, db)
    # SR-04: every new sign in clears out expired sessions, so the table does not grow.
    # Committed with whatever this request commits next.
    db.execute(delete(AuthSession).where(AuthSession.expires_at < utc_now()))
    account = db.scalar(select(Account).where(Account.username == body.username.strip()))
    if account is None or (account.locked_until is not None and account.locked_until > utc_now()):
        # SR-01: the same Argon2id work as a real check, so the response time reveals neither case
        verify_password(None, body.password)
        log(db, "auth_password_failed", account.id if account else None)
        db.commit()
        raise rejected()
    if not verify_password(account.password_hash, body.password):
        record_failure(db, account.id, "auth_password_failed")
        raise rejected()
    # SR-01: failed_logins is not reset yet. Only a correct code completes sign in.
    start_session(db, response, account.id, SessionStage.MFA_PENDING, settings.mfa_pending_minutes)


@router.post("/verify")
def verify(body: VerifyIn, request: Request, response: Response, db: DbSession) -> VerifyOut:
    """Part 2. SR-01: a correct, unused code swaps the pending session for a new signed-in one."""
    check_ip_limit(request, db)
    now = utc_now()
    token = request.cookies.get(SESSION_COOKIE)
    pending = db.get(AuthSession, hash_token(token)) if token else None
    if pending is None or pending.stage != SessionStage.MFA_PENDING or pending.expires_at <= now:
        log(db, "auth_totp_failed", None)
        db.commit()
        raise rejected()
    account = db.get_one(Account, pending.account_id)
    account_id = account.id

    secret = decrypt_or_none(account.totp_secret_enc, "accounts.totp_secret")
    step = totp_matching_step(secret, body.otp_code, now) if secret else None
    # SR-01: one UPDATE accepts the code only if its time step is newer than the last one
    # used (no replays) and the account is not locked, and clears the failure count
    accepted = (
        step is not None
        and db.execute(
            update(Account)
            .where(
                Account.id == account_id,
                or_(Account.totp_last_step.is_(None), Account.totp_last_step < step),
                or_(Account.locked_until.is_(None), Account.locked_until <= now),
            )
            .values(totp_last_step=step, failed_logins=0, locked_until=None)
            .returning(Account.id)
            .execution_options(synchronize_session=False)
        ).first()
        is not None
    )
    # SR-01: the pending session is spent, and only one request can delete it
    accepted = (
        accepted
        and db.execute(delete(AuthSession).where(AuthSession.session_id_hash == pending.session_id_hash)).rowcount
        == 1
    )
    if not accepted:
        db.rollback()
        record_failure(db, account_id, "auth_totp_failed")
        raise rejected()

    log(db, "auth_login_success", account_id)
    start_session(db, response, account_id, SessionStage.AUTHENTICATED, settings.session_minutes)
    return VerifyOut(display_name=display_name(db, account))


@router.post("/extend", status_code=status.HTTP_204_NO_CONTENT)
def extend(request: Request, response: Response, db: DbSession) -> None:
    """
    Starts a new full session. Called only when the voter chooses Keep voting.
    SR-04: one UPDATE moves the session to a new identifier with a new expiry,
    and only if it is signed in, unexpired and under MAX_SESSION_EXTENSIONS. The
    old identifier stops working at once, and of several requests carrying it
    only the first can match.
    """
    old = request.cookies.get(SESSION_COOKIE)
    now = utc_now()
    token = new_token()
    rotated = (
        db.execute(
            update(AuthSession)
            .where(
                AuthSession.session_id_hash == hash_token(old),
                AuthSession.stage == SessionStage.AUTHENTICATED,
                AuthSession.expires_at > now,
                AuthSession.extensions < settings.max_session_extensions,
            )
            .values(
                session_id_hash=hash_token(token),
                expires_at=now + timedelta(minutes=settings.session_minutes),
                extensions=AuthSession.extensions + 1,
            )
            .returning(AuthSession.account_id)
            .execution_options(synchronize_session=False)
        ).first()
        if old
        else None
    )
    if rotated is None:
        # SR-04: say why only when the session is really this voter's: the limit gets 409,
        # and an expired or unknown identifier gets the same 401 as everywhere else
        current = db.get(AuthSession, hash_token(old)) if old else None
        if current is not None and current.stage == SessionStage.AUTHENTICATED:
            limit = current.expires_at > now
            log(db, "SESSION_EXTENSION_REFUSED", current.account_id, reason="limit" if limit else "expired")
            db.commit()
            if limit:
                raise HTTPException(status.HTTP_409_CONFLICT, "extension_limit")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not_signed_in")

    log(db, "SESSION_EXTENDED", rotated.account_id)
    db.commit()
    set_cookie(response, SESSION_COOKIE, token, SESSION_PATH, secure=settings.cookie_secure)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: DbSession) -> None:
    """Ends the session, at either sign-in stage. Safe to call when already signed out."""
    # SR-01: deletes the session row on the server as well as clearing the cookie
    if token := request.cookies.get(SESSION_COOKIE):
        db.execute(delete(AuthSession).where(AuthSession.session_id_hash == hash_token(token)))
        db.commit()
    clear_cookie(response, SESSION_COOKIE, SESSION_PATH, secure=settings.cookie_secure)
