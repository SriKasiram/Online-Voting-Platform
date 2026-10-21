"""FastAPI dependencies: a database session per request, and the signed-in voter."""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Account, AccountRole, AuthSession, ElectoralRollEntry, SessionStage
from app.security import SESSION_COOKIE, hash_token, utc_now


def get_db() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session


DbSession = Annotated[Session, Depends(get_db)]


def current_session(request: Request, db: DbSession) -> AuthSession:
    """The signed-in session for this request. Refuses missing and expired sessions."""
    token = request.cookies.get(SESSION_COOKIE)
    session = db.get(AuthSession, hash_token(token)) if token else None
    # SR-01: only a session that passed both the password and the code opens /ballot,
    # /ballot/submit and /auth/extend. A session waiting for its code gets 401 here.
    if session is None or session.stage != SessionStage.AUTHENTICATED or session.expires_at <= utc_now():
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
    account = db.get_one(Account, session.account_id)
    if account.role != AccountRole.VOTER or account.roll_id is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not_a_voter")
    roll = db.get_one(ElectoralRollEntry, account.roll_id)
    if not roll.enrolled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not_enrolled")
    return Voter(account=account, roll=roll)


CurrentVoter = Annotated[Voter, Depends(current_voter)]
