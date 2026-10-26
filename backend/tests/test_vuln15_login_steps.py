"""
VULN-15: a wrong password did more work than an unknown username (an UPDATE of the account's failure
count, and possibly a DELETE of pending sessions), so the time a 401 took could tell whether a
username exists. The fix: an unknown username, a locked account and a wrong password take the same
steps (one Argon2id check, one UPDATE of accounts, one audit entry, one DELETE of pending sessions,
one commit) and get the identical 401. Measured by the steps, never by the clock.
"""

import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, event, select, update
from sqlalchemy.orm import Session

from app.models import Account
from app.routers import auth
from app.security import utc_now

LOGIN = "/api/auth/login"


@pytest.fixture
def steps(connection: Connection, monkeypatch):
    """Every SQL statement the request sends (savepoint numbers and values aside) and every password check."""
    recorded: list[str] = []
    real_verify = auth.verify_password

    def statement(conn, cursor, sql, parameters, context, executemany) -> None:
        recorded.append(re.sub(r"sa_savepoint_\d+", "sa_savepoint", " ".join(sql.split())))

    def verify_password(password_hash, password):
        # SR-01: the same Argon2id parameters whether the hash is real or the dummy
        recorded.append(f"argon2 {(password_hash or auth_dummy()).rsplit('$', 2)[0]}")
        return real_verify(password_hash, password)

    monkeypatch.setattr(auth, "verify_password", verify_password)
    event.listen(connection, "before_cursor_execute", statement)
    yield recorded
    event.remove(connection, "before_cursor_execute", statement)


def auth_dummy() -> str:
    from app import security

    return security._DUMMY_HASH


def attempt(client: TestClient, steps: list[str], username: str, password: str = "not the password at all"):
    steps.clear()
    response = client.post(LOGIN, json={"username": username, "password": password})
    return response, list(steps)


def comparable(response) -> tuple:
    headers = {k: v for k, v in response.headers.items() if k not in ("x-request-id", "date", "content-length")}
    return response.status_code, response.json(), headers


def test_unknown_locked_and_wrong_password_take_the_same_steps(
    client: TestClient, db_session: Session, make_voter, steps: list[str]
) -> None:
    """VULN-15 attack: the steps of the three failures, compared statement by statement."""
    known, locked = make_voter(), make_voter()
    db_session.execute(update(Account).where(Account.id == locked.account_id).values(failed_logins=5, locked_until=utc_now() + timedelta(minutes=15)))
    db_session.commit()

    unknown_response, unknown_steps = attempt(client, steps, "nobody.here")
    wrong_response, wrong_steps = attempt(client, steps, known.username)
    locked_response, locked_steps = attempt(client, steps, locked.username, locked.password)

    assert unknown_steps == wrong_steps == locked_steps
    assert sum(step.startswith("argon2 $argon2id$") for step in wrong_steps) == 1
    assert any(step.startswith("UPDATE accounts") for step in wrong_steps)
    assert any(step.startswith("DELETE FROM sessions WHERE sessions.account_id") for step in wrong_steps)
    assert comparable(unknown_response) == comparable(wrong_response) == comparable(locked_response)
    assert unknown_response.status_code == 401 and unknown_response.json() == {"detail": "invalid_credentials"}


def test_the_sr01_lockout_still_counts_only_real_accounts(client: TestClient, db_session: Session, make_voter, steps) -> None:
    """VULN-15, SR-01: the unknown-user UPDATE matches no row, so no account's count moves; a real one's does."""
    known = make_voter()
    attempt(client, steps, "nobody.here")
    attempt(client, steps, known.username)
    db_session.expire_all()

    counts = dict(db_session.execute(select(Account.id, Account.failed_logins)).all())
    assert counts[known.account_id] == 1 and sum(counts.values()) == 1
