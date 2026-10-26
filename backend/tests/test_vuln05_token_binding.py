"""
VULN-05: a ballot token was not bound to the session it was issued to. Whoever held a stolen token
could submit it from another signed-in session: another elector's ballot then used up the victim's
token (the victim's vote was lost, and their retry got a receipt anyway), and a replay from another
session handed out the victim's receipt. The fix: when a token is issued, an HMAC of the election
and the token is kept on the session row, keyed with an HKDF key derived from SECRET_KEY under a
fixed label (no new key file). Submit and replay compare it in constant time before anything else;
a mismatch gets the generic invalid_ballot and changes nothing. SR-04 rotation keeps it. Nothing is
added on the ballot side.
"""

import hashlib
import hmac
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from helpers import count, outcome, state_of, token_row
from app.main import app
from app.models import AuthSession, ParticipationState, PendingBallot
from app.routers import ballot as ballot_router
from app.security import SESSION_COOKIE, hash_token

SUBMIT = "/api/ballot/submit"
GENERIC = (400, {"detail": "invalid_ballot"})


def another_browser() -> TestClient:
    # SR-10: over HTTPS too, on the test's database (the client fixture's override applies to the app)
    return TestClient(app, base_url="https://testserver")


def sign_in_on(browser: TestClient, voter) -> None:
    browser.post("/api/auth/login", json={"username": voter.username, "password": voter.password})
    assert browser.post("/api/auth/verify", json={"otp_code": voter.code()}).status_code == 200


def paper(browser: TestClient) -> dict:
    response = browser.get("/api/ballot")
    assert response.status_code == 200
    return response.json()


def submit(browser: TestClient, token: str, ballot_paper: dict):
    ranking = [candidate["id"] for candidate in ballot_paper["candidates"]]
    return browser.post(SUBMIT, json={"ballot_token": token, "ranked_candidate_ids": ranking})


def test_a_stolen_token_cannot_be_used_from_another_electors_session(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """VULN-05 attack 1: the attacker, signed in with their own ballot issued, submits the victim's token."""
    victim, attacker = make_voter(), make_voter()
    sign_in(victim)
    victims = paper(client)
    thief = another_browser()
    sign_in_on(thief, attacker)
    paper(thief)

    stolen = submit(thief, victims["ballot_token"], victims)

    assert outcome(stolen) == GENERIC
    assert not token_row(db_session, victims["ballot_token"]).consumed
    assert (state_of(db_session, victim), state_of(db_session, attacker)) == (ParticipationState.ISSUED, ParticipationState.ISSUED)
    assert count(db_session, PendingBallot) == 0
    # the victim can still vote with their own token, in their own session
    assert submit(client, victims["ballot_token"], victims).status_code == 200


def test_a_used_token_replayed_from_another_session_gets_no_receipt(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """VULN-05 attack 2: after the victim voted, their token from another session must not return their receipt."""
    victim, attacker = make_voter(), make_voter()
    sign_in(victim)
    victims = paper(client)
    receipt = submit(client, victims["ballot_token"], victims).json()["receipt_id"]
    thief = another_browser()
    sign_in_on(thief, attacker)
    paper(thief)

    replayed = submit(thief, victims["ballot_token"], victims)

    assert outcome(replayed) == GENERIC and receipt not in replayed.text
    assert state_of(db_session, attacker) == ParticipationState.ISSUED
    assert count(db_session, PendingBallot) == 1


def test_the_token_does_not_outlive_its_session(client: TestClient, db_session: Session, make_voter, sign_in, clock) -> None:
    """VULN-05 attack 3: the same elector, signed out and in again, cannot use a token from the earlier session."""
    voter = make_voter()
    sign_in(voter)
    issued = paper(client)
    client.post("/api/auth/logout")
    clock.advance(seconds=30)  # a fresh authenticator code (SR-01 refuses a used one)
    assert sign_in(voter).status_code == 200

    assert outcome(submit(client, issued["ballot_token"], issued)) == GENERIC
    assert not token_row(db_session, issued["ballot_token"]).consumed


def test_the_binding_survives_session_rotation(client: TestClient, make_voter, sign_in) -> None:
    """VULN-05, SR-04: Keep voting moves the session to a new identifier; its token still works."""
    sign_in(make_voter())
    issued = paper(client)
    before = client.cookies.get(SESSION_COOKIE)
    assert client.post("/api/auth/extend").status_code == 204
    assert client.cookies.get(SESSION_COOKIE) != before

    assert submit(client, issued["ballot_token"], issued).status_code == 200


def test_the_binding_is_checked_in_constant_time(client: TestClient, make_voter, sign_in, monkeypatch) -> None:
    """VULN-05: the stored HMAC is compared with hmac.compare_digest on submit, never with ==."""
    compared = []

    def compare_digest(a, b):
        compared.append((bytes(a), bytes(b)))
        return hmac.compare_digest(a, b)

    monkeypatch.setattr(ballot_router, "hmac", SimpleNamespace(compare_digest=compare_digest))
    sign_in(make_voter())
    issued = paper(client)

    assert submit(client, issued["ballot_token"], issued).status_code == 200
    assert any(len(a) == len(b) == 32 for a, b in compared)


def test_the_binding_lives_on_the_session_and_nothing_is_added_on_the_ballot_side(
    client: TestClient, db_session: Session, engine, make_voter, sign_in
) -> None:
    """VULN-05, SR-12: a 32-byte HMAC on the identity-side session row, unlike the token's hash; ballot tables unchanged."""
    sign_in(make_voter())
    issued = paper(client)
    db_session.expire_all()
    mac = db_session.scalar(select(AuthSession.ballot_token_mac).where(AuthSession.session_id_hash == hash_token(client.cookies[SESSION_COOKIE])))
    token = issued["ballot_token"]

    assert len(mac) == 32
    assert mac not in (hash_token(token), hashlib.sha256(token.encode()).digest())
    assert token.encode() not in db_session.scalar(text("SELECT row_to_json(s)::text FROM sessions s WHERE ballot_token_mac IS NOT NULL")).encode()
    assert {c["name"] for c in inspect(engine).get_columns("ballot_tokens")} == {"id", "election_id", "token_hash", "consumed", "receipt_hash"}
