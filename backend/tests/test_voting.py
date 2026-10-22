"""Getting a ballot, submitting it once, and what gets stored."""

import json
import re
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Account, Ballot, BallotToken, ElectionStatus, ParticipationState, VoterParticipation
from app.security import hash_token


def get_ballot(client: TestClient) -> dict[str, Any]:
    response = client.get("/api/ballot")
    assert response.status_code == 200
    return response.json()


def submit(client: TestClient, ballot: dict[str, Any], ranking: list[int] | None = None):
    if ranking is None:
        ranking = [c["id"] for c in ballot["candidates"]]
    return client.post(
        "/api/ballot/submit",
        json={"ballot_token": ballot["ballot_token"], "ranked_candidate_ids": ranking},
    )


def test_voter_gets_the_ballot_for_their_division(client: TestClient, election, make_voter, sign_in) -> None:
    sign_in(make_voter(division="Southvale"))

    ballot = get_ballot(client)

    assert ballot["election_name"] == "Test election"
    assert (ballot["division_name"], ballot["state_name"]) == ("Southvale", "Victoria")
    assert [c["id"] for c in ballot["candidates"]] == [c.id for c in election.candidates["Southvale"]]
    assert [c["surname"] for c in ballot["candidates"]] == ["Ortega", "Whitfield", "Tran"]
    assert ballot["ballot_token"]


def test_voter_can_vote_once(client: TestClient, make_voter, sign_in) -> None:
    sign_in(make_voter())
    ballot = get_ballot(client)

    response = submit(client, ballot, [c["id"] for c in reversed(ballot["candidates"])])

    assert response.status_code == 200
    assert re.fullmatch(r"[A-Z2-9]{4}-[A-Z2-9]{4}", response.json()["receipt_id"])
    again = client.get("/api/ballot")
    assert again.status_code == 409
    assert again.json() == {"detail": "already_voted"}


def test_stored_ballot_holds_the_preferences_and_nothing_about_the_voter(
    client: TestClient, db_session: Session, election, make_voter, sign_in
) -> None:
    """SR-03: the token is found by its hex hash, and participation by the roll entry."""
    voter = make_voter()
    sign_in(voter)
    ballot = get_ballot(client)
    ranking = [c["id"] for c in reversed(ballot["candidates"])]

    assert submit(client, ballot, ranking).status_code == 200

    stored = db_session.scalars(select(Ballot)).one()
    assert json.loads(stored.ciphertext) == ranking  # Stage 2: plain JSON placeholder
    token_hash = hash_token(ballot["ballot_token"]).hex()
    token = db_session.scalars(select(BallotToken).where(BallotToken.token_hash == token_hash)).one()
    assert token.consumed_at is not None
    roll_id = db_session.get_one(Account, voter.account_id).roll_id
    participation = db_session.get_one(VoterParticipation, (roll_id, election.election.id))
    assert participation.state == ParticipationState.VOTED


def test_ballot_token_works_only_once(client: TestClient, make_voter, sign_in) -> None:
    first, second = make_voter(), make_voter()
    sign_in(first)
    ballot = get_ballot(client)
    assert submit(client, ballot).status_code == 200
    client.post("/api/auth/logout")

    sign_in(second)
    response = submit(client, ballot)

    assert response.status_code == 400
    assert response.json() == {"detail": "invalid_ballot"}
    # The rejected attempt did not count as this voter's vote
    assert client.get("/api/ballot").status_code == 200


@pytest.mark.parametrize("problem", ["missing a candidate", "candidate twice", "other division"])
def test_ballot_must_number_every_candidate_once(
    client: TestClient, election, make_voter, sign_in, problem: str
) -> None:
    """SR-03: after a rejected ballot the same token still works, since a second ballot request is refused."""
    sign_in(make_voter())
    ballot = get_ballot(client)
    ids = [c["id"] for c in ballot["candidates"]]
    if problem == "missing a candidate":
        ranking = ids[:-1]
    elif problem == "candidate twice":
        ranking = [*ids[:-1], ids[0]]
    else:
        ranking = [*ids[:-1], election.candidates["Southvale"][0].id]

    response = submit(client, ballot, ranking)

    assert response.status_code == 400
    assert response.json() == {"detail": "invalid_ballot"}
    # A rejected ballot does not use up the voter's vote
    assert submit(client, ballot).status_code == 200


def test_ballot_needs_a_signed_in_voter(client: TestClient) -> None:
    assert client.get("/api/ballot").status_code == 401
    assert client.post(
        "/api/ballot/submit", json={"ballot_token": "x", "ranked_candidate_ids": [1]}
    ).status_code == 401


@pytest.mark.parametrize(
    ("kind", "reason"),
    [({"enrolled": False}, "not_enrolled"), ({"official": True}, "forbidden")],
)
def test_accounts_that_cannot_vote_get_no_ballot(
    client: TestClient, election, make_voter, sign_in, kind: dict, reason: str
) -> None:
    """SR-05: a staff account now gets "forbidden" (it was "not_a_voter")."""
    sign_in(make_voter(**kind))

    response = client.get("/api/ballot")

    assert response.status_code == 403
    assert response.json() == {"detail": reason}


def test_no_ballot_when_no_election_is_open(
    client: TestClient, db_session: Session, election, make_voter, sign_in
) -> None:
    election.election.status = ElectionStatus.CLOSED
    db_session.commit()
    sign_in(make_voter())

    response = client.get("/api/ballot")

    assert response.status_code == 404
    assert response.json() == {"detail": "no_open_election"}
