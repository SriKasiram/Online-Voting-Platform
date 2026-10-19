"""
Sign-in sessions, the cookies that carry them, and the dependencies that
protect the voter endpoints.

Stage 2: tokens are stored as they are in the *_hash columns, and the cookies
are not marked Secure yet. A later stage stores only a hash of each token and
serves everything over HTTPS.
"""

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Response, status

from app.database import DbSession
from app.models import Account, AccountRole, AuthSession, ElectoralRollEntry

SESSION_COOKIE = "session_id"
SESSION_PATH = "/api"

CHALLENGE_COOKIE = "login_challenge"
CHALLENGE_PATH = "/api/auth"


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_token() -> str:
    """A random, unguessable value for a cookie or a ballot token."""
    return secrets.token_urlsafe(32)


def set_cookie(response: Response, name: str, value: str, path: str, max_age: int | None = None) -> None:
    # HttpOnly keeps the token away from page scripts. SameSite=Strict stops other sites sending it.
    response.set_cookie(name, value, path=path, max_age=max_age, httponly=True, samesite="strict")


def clear_cookie(response: Response, name: str, path: str) -> None:
    response.delete_cookie(name, path=path, httponly=True, samesite="strict")


def current_session(request: Request, db: DbSession) -> AuthSession:
    """The signed-in session for this request. Refuses missing and expired sessions."""
    token = request.cookies.get(SESSION_COOKIE)
    session = db.get(AuthSession, token.encode()) if token else None
    if session is None or session.expires_at <= utc_now():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not_signed_in")
    session.last_seen = utc_now()
    return session


CurrentSession = Annotated[AuthSession, Depends(current_session)]


@dataclass
class Voter:
    account: Account
    roll: ElectoralRollEntry


def current_voter(session: CurrentSession, db: DbSession) -> Voter:
    """The signed-in account, if it is allowed to vote: a voter who is enrolled."""
    account = db.get(Account, session.account_id)
    if account is None or account.role != AccountRole.VOTER or account.roll_id is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not_a_voter")
    roll = db.get(ElectoralRollEntry, account.roll_id)
    if roll is None or not roll.enrolled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not_enrolled")
    return Voter(account=account, roll=roll)


CurrentVoter = Annotated[Voter, Depends(current_voter)]
