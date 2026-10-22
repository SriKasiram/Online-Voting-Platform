"""FastAPI dependencies: a database session per request, and the signed-in voter."""

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Account, AccountRole, AuthSession, SessionStage
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
    # SR-04: activity is recorded, but never moves expires_at
    session.last_seen = utc_now()
    return session


CurrentSession = Annotated[AuthSession, Depends(current_session)]


def current_elector(session: CurrentSession, db: DbSession) -> Account:
    """
    The signed-in account, if it is an elector linked to the roll.
    SR-05: used only by the voting routes. The role is read from the database on
    every request, and staff get 403 forbidden (previously "not_a_voter").
    """
    account = db.get_one(Account, session.account_id)
    if account.role != AccountRole.ELECTOR or account.roll_id is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
    # SR-02: enrolment, division and age now come from the signed roll record
    # (app/eligibility.py), so the unsigned roll row is no longer read here
    return account


# SR-05: renamed from CurrentVoter
CurrentElector = Annotated[Account, Depends(current_elector)]
