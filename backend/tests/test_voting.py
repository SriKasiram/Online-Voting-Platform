"""Getting a ballot, submitting it once, and what gets stored."""

import json
import re
from typing import Any

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    Account,
    AccountRole,
    Ballot,
    BallotToken,
    Candidate,
    Division,
    Election,
    ElectionStatus,
    ElectoralRollEntry,
    VoterParticipation,
)
from scripts.seed import (
    CANDIDATES,
    DEMO_CODE,
    DEMO_PASSWORD,
    DIVISIONS,
    ELECTION_NAME,
    OFFICIAL_USERNAME,
    voter_accounts,
)

# The tests use whichever accounts scripts/seed.py defines
VOTER = next(voter for voter in voter_accounts() if voter.enrolled)
CANNOT_VOTE = [(OFFICIAL_USERNAME, "not_a_voter")] + [
    (voter.username, "not_enrolled") for voter in voter_accounts() if not voter.enrolled
][:1]


def sign_in(client: TestClient, username: str) -> None:
    client.post("/api/auth/login", json={"username": username, "password": DEMO_PASSWORD})
    assert client.post("/api/auth/verify", json={"otp_code": DEMO_CODE}).status_code == 200


def get_ballot(client: TestClient) -> dict[str, Any]:
    response = client.get("/api/ballot")
    assert response.status_code == 200
    return response.json()


def submit(client: TestClient, ballot: dict[str, Any], ranking: list[int] | None = None) -> Response:
    if ranking is None:
        ranking = [c["id"] for c in ballot["candidates"]]
    return client.post(
        "/api/ballot/submit",
        json={"ballot_token": ballot["ballot_token"], "ranked_candidate_ids": ranking},
    )


def test_voter_gets_the_ballot_for_their_division(client: TestClient) -> None:
    sign_in(client, VOTER.username)

    ballot = get_ballot(client)

    assert ballot["election_name"] == ELECTION_NAME
    assert (ballot["division_name"], ballot["state_name"]) == (VOTER.division, DIVISIONS[VOTER.division])
    assert [(c["given_name"], c["surname"], c["party"]) for c in ballot["candidates"]] == CANDIDATES[
        VOTER.division
    ]
    assert ballot["ballot_token"]


def test_voter_can_vote_once(client: TestClient) -> None:
    sign_in(client, VOTER.username)
    ballot = get_ballot(client)

    response = submit(client, ballot, [c["id"] for c in reversed(ballot["candidates"])])

    assert response.status_code == 200
    assert re.fullmatch(r"[A-Z2-9]{4}-[A-Z2-9]{4}", response.json()["receipt_id"])
    again = client.get("/api/ballot")
    assert again.status_code == 409
    assert again.json() == {"detail": "already_voted"}


def test_stored_ballot_holds_the_preferences_and_nothing_about_the_voter(
    client: TestClient, db_session: Session
) -> None:
    sign_in(client, VOTER.username)
    ballot = get_ballot(client)
    ranking = [c["id"] for c in reversed(ballot["candidates"])]

    assert submit(client, ballot, ranking).status_code == 200

    stored = db_session.scalars(select(Ballot)).one()
    assert json.loads(stored.ciphertext) == ranking  # Stage 2: plain JSON placeholder
    token = db_session.get(BallotToken, ballot["ballot_token"].encode())
    assert token is not None and token.used
    account = db_session.scalars(select(Account).where(Account.username == VOTER.username)).one()
    election = db_session.scalars(select(Election)).one()
    assert db_session.get(VoterParticipation, (account.id, election.id)) is not None


def test_ballot_token_works_only_once(client: TestClient, db_session: Session) -> None:
    # A second voter in the same division, so the token can be tried by someone who has not voted
    division = db_session.scalars(select(Division).where(Division.name == VOTER.division)).one()
    roll = ElectoralRollEntry(
        roll_lookup=b"TEST-0001",
        full_name_enc=b"Test Voter",
        address_enc=b"1 Test Street, Carlton VIC 3053",
        division_id=division.id,
        enrolled=True,
    )
    db_session.add(roll)
    db_session.flush()
    db_session.add(
        Account(
            username="second.voter",
            password_hash=DEMO_PASSWORD,
            role=AccountRole.VOTER,
            roll_id=roll.id,
            totp_secret_enc=DEMO_CODE.encode(),
        )
    )
    db_session.commit()

    sign_in(client, VOTER.username)
    ballot = get_ballot(client)
    assert submit(client, ballot).status_code == 200
    client.post("/api/auth/logout")

    sign_in(client, "second.voter")
    response = submit(client, ballot)

    assert response.status_code == 400
    assert response.json() == {"detail": "invalid_ballot"}
    # The rejected attempt did not count as this voter's vote
    assert client.get("/api/ballot").status_code == 200


@pytest.mark.parametrize("problem", ["missing a candidate", "candidate twice", "other division"])
def test_ballot_must_number_every_candidate_once(
    client: TestClient, db_session: Session, problem: str
) -> None:
    sign_in(client, VOTER.username)
    ballot = get_ballot(client)
    ids = [c["id"] for c in ballot["candidates"]]
    if problem == "missing a candidate":
        ranking = ids[:-1]
    elif problem == "candidate twice":
        ranking = [*ids[:-1], ids[0]]
    else:
        other_division = next(name for name in DIVISIONS if name != VOTER.division)
        other_candidate = db_session.scalars(
            select(Candidate.id)
            .join(Division, Candidate.division_id == Division.id)
            .where(Division.name == other_division)
        ).first()
        ranking = [*ids[:-1], other_candidate]

    response = submit(client, ballot, ranking)

    assert response.status_code == 400
    assert response.json() == {"detail": "invalid_ballot"}
    # A rejected ballot does not use up the voter's vote
    assert client.get("/api/ballot").status_code == 200


def test_ballot_needs_a_signed_in_voter(client: TestClient) -> None:
    assert client.get("/api/ballot").status_code == 401
    assert client.post(
        "/api/ballot/submit", json={"ballot_token": "x", "ranked_candidate_ids": [1]}
    ).status_code == 401


@pytest.mark.parametrize(("username", "reason"), CANNOT_VOTE)
def test_accounts_that_cannot_vote_get_no_ballot(client: TestClient, username: str, reason: str) -> None:
    sign_in(client, username)

    response = client.get("/api/ballot")

    assert response.status_code == 403
    assert response.json() == {"detail": reason}


def test_no_ballot_when_no_election_is_open(client: TestClient, db_session: Session) -> None:
    db_session.scalars(select(Election)).one().status = ElectionStatus.CLOSED
    db_session.commit()
    sign_in(client, VOTER.username)

    response = client.get("/api/ballot")

    assert response.status_code == 404
    assert response.json() == {"detail": "no_open_election"}
