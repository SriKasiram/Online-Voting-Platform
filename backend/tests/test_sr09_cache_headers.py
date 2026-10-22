"""
SR-09: no browser or proxy may keep a copy of an API response. Every response,
success, error or redirect, carries Cache-Control: no-store and Pragma: no-cache.
"""

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.config import settings
from app.models import BallotDefinition

UNKNOWN_USER = {"username": "nobody.here", "password": "not the right password"}


def assert_not_cached(response: Response) -> None:
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


@pytest.mark.parametrize(
    ("expected", "send"),
    [
        pytest.param(200, lambda c: c.get("/api/health"), id="health"),
        pytest.param(401, lambda c: c.post("/api/auth/login", json=UNKNOWN_USER), id="login-refused"),
        pytest.param(401, lambda c: c.get("/api/ballot"), id="not-signed-in-from-a-dependency"),
        pytest.param(404, lambda c: c.get("/api/no-such-route"), id="unknown-path"),
        pytest.param(422, lambda c: c.post("/api/auth/login", json={}), id="invalid-body"),
        pytest.param(307, lambda c: c.get("/api/health/", follow_redirects=False), id="redirect"),
    ],
)
def test_no_store_without_a_session(client: TestClient, expected: int, send: Callable[[TestClient], Response]) -> None:
    """SR-09 test 1: health, a refused login, a missing session, an unknown path, an invalid body and a redirect."""
    response = send(client)

    assert response.status_code == expected
    assert_not_cached(response)


def test_no_store_on_the_ballot_and_submit(client: TestClient, make_voter, sign_in) -> None:
    """SR-09 test 2: sign-in, the signed-in ballot, a refused ranking (SR-08) and the accepted submit."""
    signed_in = sign_in(make_voter())
    ballot = client.get("/api/ballot")
    token, ids = ballot.json()["ballot_token"], [c["id"] for c in ballot.json()["candidates"]]
    refused = client.post("/api/ballot/submit", json={"ballot_token": token, "ranked_candidate_ids": ids[:1]})
    accepted = client.post("/api/ballot/submit", json={"ballot_token": token, "ranked_candidate_ids": ids})

    assert [r.status_code for r in (signed_in, ballot, refused, accepted)] == [200, 200, 422, 200]
    for response in (signed_in, ballot, refused, accepted):
        assert_not_cached(response)


def test_no_store_when_sign_in_is_rate_limited(
    client: TestClient, make_voter, sign_in, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-09 test 3: the SR-01 rate limit answer (429)."""
    sign_in(make_voter())
    monkeypatch.setattr(settings, "rate_limit_attempts", 2)
    limited = client.post("/api/auth/login", json=UNKNOWN_USER)

    assert limited.status_code == 429
    assert_not_cached(limited)


def test_no_store_when_the_ballot_is_unavailable(client: TestClient, db_session: Session, make_voter, sign_in) -> None:
    """SR-09 test 4: the SR-07 fail-closed answer (503) when no signed ballot definition exists."""
    voter = make_voter()
    db_session.execute(delete(BallotDefinition))
    db_session.commit()
    sign_in(voter)
    unavailable = client.get("/api/ballot")

    assert unavailable.status_code == 503
    assert_not_cached(unavailable)
