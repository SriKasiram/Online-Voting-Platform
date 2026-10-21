"""
Sign in, in two parts (password, then a code from the voter's authenticator
app), then extend or end the session.
"""

from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import CHALLENGE_MINUTES, settings
from app.deps import CurrentSession, DbSession
from app.models import Account, AccountRole, AuthSession, ElectoralRollEntry, LoginChallenge
from app.schemas import LoginIn, VerifyIn, VerifyOut
from app.security import (
    CHALLENGE_COOKIE,
    CHALLENGE_PATH,
    SESSION_COOKIE,
    SESSION_PATH,
    clear_cookie,
    decrypt_or_none,
    hash_token,
    new_token,
    set_cookie,
    utc_now,
    verify_password,
    verify_totp,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def display_name(db: Session, account: Account) -> str:
    if account.role == AccountRole.ELECTION_OFFICIAL:
        return "Election official"
    roll = db.get(ElectoralRollEntry, account.roll_id) if account.roll_id else None
    name = decrypt_or_none(roll.full_name_enc, "electoral_roll.full_name") if roll else None
    return name or account.username


def code_is_right(account: Account, code: str) -> bool:
    secret = decrypt_or_none(account.totp_secret_enc, "accounts.totp_secret")
    return secret is not None and verify_totp(secret, code)


@router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
def login(body: LoginIn, response: Response, db: DbSession) -> None:
    """Part 1. Answers the same way whether or not the username and password are right."""
    challenge_id = new_token()
    account = db.scalar(select(Account).where(Account.username == body.username.strip()))
    # Checked even when there is no account, so an unknown username takes as long as a wrong password
    if verify_password(account.password_hash if account else None, body.password) and account:
        db.add(
            LoginChallenge(
                challenge_id_hash=hash_token(challenge_id),
                account_id=account.id,
                expires_at=utc_now() + timedelta(minutes=CHALLENGE_MINUTES),
            )
        )
        db.commit()
    # Wrong details still get a cookie. It matches nothing, so the code step fails
    # with the same message as a wrong code.
    set_cookie(response, CHALLENGE_COOKIE, challenge_id, CHALLENGE_PATH, max_age=CHALLENGE_MINUTES * 60)


@router.post("/verify")
def verify(body: VerifyIn, request: Request, response: Response, db: DbSession) -> VerifyOut:
    """Part 2. Swaps a passed challenge for a signed-in session."""
    token = request.cookies.get(CHALLENGE_COOKIE)
    challenge = db.get(LoginChallenge, hash_token(token)) if token else None
    account = db.get_one(Account, challenge.account_id) if challenge else None
    if (
        challenge is None
        or account is None
        or challenge.expires_at <= utc_now()
        or not code_is_right(account, body.otp_code)
    ):
        # The challenge stays, so a mistyped code can be tried again
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "sign_in_failed")

    # A brand new session id, never the challenge id, so an id seen before sign in is useless after it
    session_id = new_token()
    db.delete(challenge)
    db.add(
        AuthSession(
            session_id_hash=hash_token(session_id),
            account_id=account.id,
            expires_at=utc_now() + timedelta(minutes=settings.session_minutes),
        )
    )
    db.commit()

    clear_cookie(response, CHALLENGE_COOKIE, CHALLENGE_PATH)
    set_cookie(response, SESSION_COOKIE, session_id, SESSION_PATH)
    return VerifyOut(display_name=display_name(db, account))


@router.post("/extend", status_code=status.HTTP_204_NO_CONTENT)
def extend(session: CurrentSession, db: DbSession) -> None:
    """Starts a new full session. Called only when the voter chooses Keep voting."""
    session.expires_at = utc_now() + timedelta(minutes=settings.session_minutes)
    db.commit()


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: DbSession) -> None:
    """Ends the session and any half-finished sign in. Safe to call when already signed out."""
    if token := request.cookies.get(SESSION_COOKIE):
        db.execute(delete(AuthSession).where(AuthSession.session_id_hash == hash_token(token)))
    if token := request.cookies.get(CHALLENGE_COOKIE):
        db.execute(delete(LoginChallenge).where(LoginChallenge.challenge_id_hash == hash_token(token)))
    db.commit()
    clear_cookie(response, SESSION_COOKIE, SESSION_PATH)
    clear_cookie(response, CHALLENGE_COOKIE, CHALLENGE_PATH)
