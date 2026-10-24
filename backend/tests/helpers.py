"""
Test helpers shared by several test modules, so each exists once (imported as `from helpers import ...`).
Fixtures every test can use live in conftest.py; these are plain functions and one fixture base class.
"""

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session

from app.db import Base
from app.deps import get_db
from app.main import app
from app.models import Account, AuditLogEntry, BallotToken, ParticipationState, VoterParticipation


def outcome(response) -> tuple[int, dict]:
    # SR-02, SR-03, SR-04, SR-06, SR-07, SR-08: a response as (status, JSON body)
    return response.status_code, response.json()


def start_api() -> None:
    """SR-02, SR-07, SR-11: the API's real start-up (its lifespan), as uvicorn runs it. The client fixture has pointed it at the test database."""
    with TestClient(app):
        pass


def last_id(db_session: Session) -> int:
    # SR-05, SR-06: the newest audit entry's id, so a test reads only the entries it caused
    return db_session.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))


def count(db_session: Session, model, *where) -> int:
    # SR-03, SR-08, SR-14: rows of a table, optionally filtered, read fresh
    db_session.expire_all()
    query = select(func.count()).select_from(model)
    return db_session.scalar(query.where(*where) if where else query)


def state_of(db: Session, voter) -> ParticipationState:
    # SR-08, SR-14: the voter's participation state, read fresh
    db.expire_all()
    roll_id = db.get_one(Account, voter.account_id).roll_id
    return db.scalars(select(VoterParticipation.state).where(VoterParticipation.roll_id == roll_id)).one()


def token_row(db: Session, token: str) -> BallotToken:
    # SR-03, SR-14: a ballot token's row, found by the SHA-256 of the token
    db.expire_all()
    digest = hashlib.sha256(token.encode()).hexdigest()
    return db.scalars(select(BallotToken).where(BallotToken.token_hash == digest)).one()


def account_row(db: Session, user) -> Account:
    # SR-01, SR-06: the account's row, read fresh
    db.expire_all()
    return db.get_one(Account, user.account_id)


def _set_append_only_triggers(db: Session, tables: tuple[str, ...], state: str) -> None:
    for table in tables:
        db.execute(text(f"ALTER TABLE {table} {state} TRIGGER {table}_append_only"))


@contextmanager
def triggers_off(db: Session, *tables: str, commit: bool = False) -> Iterator[None]:
    """
    SR-13, SR-17: tampering as only a database owner could, inside the test only; the append-only
    triggers are back on afterwards. SR-17 works on committed data, so it also commits then (commit=True).
    """
    _set_append_only_triggers(db, tables, "DISABLE")
    try:
        yield
    finally:
        _set_append_only_triggers(db, tables, "ENABLE")
        if commit:
            db.commit()


def committed_triggers_off(db: Session, *tables: str):
    # SR-17: triggers_off for committed data
    return triggers_off(db, *tables, commit=True)


class CommittedDatabase:
    """
    SR-03, SR-14, SR-17: real, separate transactions. A second connection only sees committed rows,
    so these replace the db_session and client fixtures with committing ones, and empty the test
    database afterwards (TRUNCATE, which the append-only triggers do not stop).
    """

    @pytest.fixture
    def db_session(self, engine: Engine) -> Iterator[Session]:
        with Session(engine) as session:
            yield session
        with engine.begin() as connection:
            tables = ", ".join(table.name for table in Base.metadata.sorted_tables)
            connection.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))

    @pytest.fixture
    def client(self, engine: Engine) -> Iterator[TestClient]:
        def real_db() -> Iterator[Session]:
            with Session(engine) as session:
                yield session

        app.dependency_overrides[get_db] = real_db
        yield TestClient(app, base_url="https://testserver")
        app.dependency_overrides.clear()
