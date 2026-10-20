"""Two-part sign in with the seeded accounts. Stage 2: plain demo password and code."""

from datetime import timedelta

from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuthSession
from app.sessions import utc_now
from scripts.seed import DEMO_CODE, DEMO_PASSWORD, voter_accounts

# Whichever enrolled voter scripts/seed.py lists first
VOTER = next(voter for voter in voter_accounts() if voter.enrolled)


def enter_details(client: TestClient, username: str, password: str = DEMO_PASSWORD) -> Response:
    return client.post("/api/auth/login", json={"username": username, "password": password})


def enter_code(client: TestClient, code: str = DEMO_CODE) -> Response:
    return client.post("/api/auth/verify", json={"otp_code": code})


def test_right_details_and_code_sign_the_voter_in(client: TestClient) -> None:
    assert enter_details(client, VOTER.username).status_code == 204

    response = enter_code(client)

    assert response.status_code == 200
    assert response.json() == {"display_name": VOTER.full_name}
    assert "session_id" in response.cookies


def test_username_ignores_letter_case(client: TestClient) -> None:
    enter_details(client, VOTER.username.upper())

    assert enter_code(client).status_code == 200


def test_wrong_password_looks_like_success_until_the_code_step(client: TestClient) -> None:
    # Part 1 answers exactly as it would for the right password
    assert enter_details(client, VOTER.username, password="wrong").status_code == 204

    response = enter_code(client)

    assert response.status_code == 401
    assert response.json() == {"detail": "sign_in_failed"}


def test_unknown_username_looks_like_success_until_the_code_step(client: TestClient) -> None:
    assert enter_details(client, "nobody.here").status_code == 204

    assert enter_code(client).status_code == 401


def test_wrong_code_fails_and_the_voter_can_try_again(client: TestClient) -> None:
    enter_details(client, VOTER.username)

    assert enter_code(client, "000000").status_code == 401
    assert enter_code(client).status_code == 200


def test_code_step_without_the_password_step_fails(client: TestClient) -> None:
    assert enter_code(client).status_code == 401


def test_logout_ends_the_session(client: TestClient) -> None:
    enter_details(client, VOTER.username)
    enter_code(client)

    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/ballot").status_code == 401


def test_expired_session_is_refused(client: TestClient, db_session: Session) -> None:
    enter_details(client, VOTER.username)
    enter_code(client)
    session = db_session.scalars(select(AuthSession)).one()
    session.expires_at = utc_now() - timedelta(seconds=1)
    db_session.commit()

    response = client.get("/api/ballot")

    assert response.status_code == 401
    assert response.json() == {"detail": "not_signed_in"}


def test_extend_starts_a_new_full_session(client: TestClient, db_session: Session) -> None:
    enter_details(client, VOTER.username)
    enter_code(client)
    session = db_session.scalars(select(AuthSession)).one()
    session.expires_at = utc_now() + timedelta(seconds=30)
    db_session.commit()

    assert client.post("/api/auth/extend").status_code == 204

    db_session.expire_all()
    almost_full = utc_now() + timedelta(minutes=settings.session_minutes) - timedelta(seconds=10)
    assert db_session.scalars(select(AuthSession)).one().expires_at > almost_full
