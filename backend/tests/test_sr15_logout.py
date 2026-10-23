"""
SR-15: every finished or abandoned session ends with the frontend's terminal reset, which calls
POST /api/auth/logout. Logout must end the session for good, clear the cookie exactly as it was
set, answer the same way whatever state the session is in (a reset may follow another reset or an
expired session), and write nothing to the audit log.
"""

from datetime import timedelta
from http.cookies import SimpleCookie

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.main import app
from app.models import AuditLogEntry, AuthSession
from app.security import SESSION_COOKIE, hash_token, new_token, utc_now

LOGOUT = "/api/auth/logout"
NOT_SIGNED_IN = (401, {"detail": "not_signed_in"})


@pytest.fixture(autouse=True)
def secure_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-15: the shipped setting (SR-10), whatever backend/.env says."""
    monkeypatch.setattr(settings, "cookie_secure", True)


def as_session(token: str | None) -> TestClient:
    """A client that presents exactly this cookie, or none, and nothing else."""
    headers = {"cookie": f"{SESSION_COOKIE}={token}"} if token else {}
    return TestClient(app, base_url="https://testserver", headers=headers)


def cookie_attributes(set_cookie: str) -> dict[str, str | bool]:
    morsel = SimpleCookie(set_cookie)[SESSION_COOKIE]
    return {name: morsel[name] for name in ("path", "httponly", "samesite", "secure", "domain")}


def row(db_session: Session, token: str) -> AuthSession | None:
    db_session.expire_all()
    return db_session.get(AuthSession, hash_token(token))


def audit_count(db_session: Session) -> int:
    db_session.expire_all()
    return db_session.scalar(select(func.count()).select_from(AuditLogEntry))


def test_logout_deletes_the_session_and_expires_the_cookie_as_it_was_set(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-15 test 1: the row is gone, and Set-Cookie expires the cookie with the same Secure, HttpOnly, Strict and path."""
    signed_in = sign_in(make_voter())
    token = client.cookies[SESSION_COOKIE]
    assert row(db_session, token) is not None

    response = client.post(LOGOUT)

    assert response.status_code == 204
    assert row(db_session, token) is None
    cleared = SimpleCookie(response.headers["set-cookie"])[SESSION_COOKIE]
    assert cleared.value == "" and cleared["max-age"] == "0"
    assert cookie_attributes(response.headers["set-cookie"]) == cookie_attributes(signed_in.headers["set-cookie"])
    assert cookie_attributes(response.headers["set-cookie"]) == {
        "path": "/",
        "httponly": True,
        "samesite": "strict",
        "secure": True,
        "domain": "",
    }


def test_old_cookie_is_refused_on_elector_routes_after_logout(client: TestClient, make_voter, sign_in) -> None:
    """SR-15 test 2: a copy of the old cookie, kept by someone at the terminal, opens nothing after the reset."""
    sign_in(make_voter())
    token = client.cookies[SESSION_COOKIE]
    ballot = client.get("/api/ballot").json()
    client.post(LOGOUT)

    old = as_session(token)

    assert (old.get("/api/ballot").status_code, old.get("/api/ballot").json()) == NOT_SIGNED_IN
    submitted = old.post(
        "/api/ballot/submit",
        json={"ballot_token": ballot["ballot_token"], "ranked_candidate_ids": [c["id"] for c in ballot["candidates"]]},
    )
    assert (submitted.status_code, submitted.json()) == NOT_SIGNED_IN
    assert (old.post("/api/auth/extend").status_code, old.post("/api/auth/extend").json()) == NOT_SIGNED_IN


@pytest.mark.parametrize("cookie", ["none", "unknown", "expired", "pending (code step)", "already logged out"])
def test_logout_answers_the_same_whatever_the_session_state(
    client: TestClient, db_session: Session, make_voter, sign_in, cookie: str
) -> None:
    """SR-15 test 3: no cookie, an unknown or expired one, a code-step one, or a second reset: all 204, all cleared."""
    voter = make_voter()
    token: str | None = None
    if cookie == "unknown":
        token = new_token()
    elif cookie == "expired":
        sign_in(voter)
        token = client.cookies[SESSION_COOKIE]
        session = db_session.get_one(AuthSession, hash_token(token))
        session.expires_at = utc_now() - timedelta(seconds=1)
        db_session.commit()
    elif cookie == "pending (code step)":
        client.post("/api/auth/login", json={"username": voter.username, "password": voter.password})
        token = client.cookies[SESSION_COOKIE]
    elif cookie == "already logged out":
        sign_in(voter)
        token = client.cookies[SESSION_COOKIE]
        assert as_session(token).post(LOGOUT).status_code == 204

    response = as_session(token).post(LOGOUT)

    assert response.status_code == 204 and response.content == b""
    assert SimpleCookie(response.headers["set-cookie"])[SESSION_COOKIE]["max-age"] == "0"
    if token:
        assert row(db_session, token) is None


def test_logout_writes_no_audit_entry(client: TestClient, db_session: Session, make_voter, sign_in) -> None:
    """SR-15 test 4: repeated resets add nothing to the audit log, signed in or not."""
    sign_in(make_voter())
    token = client.cookies[SESSION_COOKIE]
    before = audit_count(db_session)

    client.post(LOGOUT)
    for again in (token, None, new_token(), token):
        as_session(again).post(LOGOUT)

    assert audit_count(db_session) == before
