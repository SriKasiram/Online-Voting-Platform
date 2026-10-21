"""Two-part sign in: Argon2 password, then a code from the voter's authenticator app."""

from datetime import timedelta

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuthSession
from app.security import hash_token, utc_now


def wrong_code(secret: str) -> str:
    """A 6-digit code that is not valid now, nor one step either side."""
    totp = pyotp.TOTP(secret)
    now = utc_now()
    valid = {totp.at(now + timedelta(seconds=s)) for s in (-30, 0, 30)}
    return next(code for code in ("000000", "111111", "222222", "333333") if code not in valid)


def enter_details(client: TestClient, username: str, password: str):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def test_right_details_and_code_sign_the_voter_in(make_voter, sign_in) -> None:
    voter = make_voter()

    response = sign_in(voter)

    assert response.status_code == 200
    assert response.json() == {"display_name": voter.full_name}
    assert "session_id" in response.cookies


def test_username_ignores_letter_case(client: TestClient, make_voter) -> None:
    voter = make_voter()
    enter_details(client, voter.username.upper(), voter.password)

    assert client.post("/api/auth/verify", json={"otp_code": voter.code()}).status_code == 200


def test_wrong_password_looks_like_success_until_the_code_step(client: TestClient, make_voter) -> None:
    voter = make_voter()
    # Part 1 answers exactly as it would for the right password
    assert enter_details(client, voter.username, "not the password").status_code == 204

    response = client.post("/api/auth/verify", json={"otp_code": voter.code()})

    assert response.status_code == 401
    assert response.json() == {"detail": "sign_in_failed"}


def test_unknown_username_looks_like_success_until_the_code_step(client: TestClient) -> None:
    assert enter_details(client, "nobody.here", "any password at all").status_code == 204

    assert client.post("/api/auth/verify", json={"otp_code": "123456"}).status_code == 401


def test_wrong_code_fails_and_the_voter_can_try_again(client: TestClient, make_voter) -> None:
    voter = make_voter()
    enter_details(client, voter.username, voter.password)

    assert client.post("/api/auth/verify", json={"otp_code": wrong_code(voter.totp_secret)}).status_code == 401
    assert client.post("/api/auth/verify", json={"otp_code": voter.code()}).status_code == 200


def test_code_step_without_the_password_step_fails(client: TestClient) -> None:
    assert client.post("/api/auth/verify", json={"otp_code": "123456"}).status_code == 401


def test_session_token_is_stored_only_as_a_hash(db_session: Session, make_voter, sign_in) -> None:
    token = sign_in(make_voter()).cookies["session_id"]

    stored = db_session.scalars(select(AuthSession)).one()

    assert stored.session_id_hash == hash_token(token)
    assert token.encode() not in stored.session_id_hash


def test_logout_ends_the_session(client: TestClient, make_voter, sign_in) -> None:
    sign_in(make_voter())

    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/ballot").status_code == 401


def test_expired_session_is_refused(client: TestClient, db_session: Session, make_voter, sign_in) -> None:
    sign_in(make_voter())
    session = db_session.scalars(select(AuthSession)).one()
    session.expires_at = utc_now() - timedelta(seconds=1)
    db_session.commit()

    response = client.get("/api/ballot")

    assert response.status_code == 401
    assert response.json() == {"detail": "not_signed_in"}


def test_extend_starts_a_new_full_session(client: TestClient, db_session: Session, make_voter, sign_in) -> None:
    sign_in(make_voter())
    session = db_session.scalars(select(AuthSession)).one()
    session.expires_at = utc_now() + timedelta(seconds=30)
    db_session.commit()

    assert client.post("/api/auth/extend").status_code == 204

    db_session.expire_all()
    almost_full = utc_now() + timedelta(minutes=settings.session_minutes) - timedelta(seconds=10)
    assert db_session.scalars(select(AuthSession)).one().expires_at > almost_full
