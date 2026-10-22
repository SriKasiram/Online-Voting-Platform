"""
SR-08: House preferences are checked on the server before the ballot token is
used. Every candidate must be numbered once; anything less is informal and
anything impossible from the interface is invalid. Neither is stored, and the
same token can be used again.
"""

import itertools
import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

# SR-11: ballots are stored encrypted
from app.ballot_crypto import RANKING_FIELD, decrypt_ballot
from app.ballot_rules import Verdict, evaluate_house_ballot
from app.models import Account, AuditLogEntry, Ballot, BallotToken, Candidate, ParticipationState, VoterParticipation
from app.routers import ballot as ballot_router
from scripts.ballot_definition import build_payload, sign, store_active

A, B, C, D = 11, 12, 13, 14
FOUR = [A, B, C, D]
FORMAL = Verdict("formal")
INCOMPLETE = Verdict("informal", "incomplete_order")
BLANK = Verdict("informal", "blank")


@pytest.fixture
def northgate(db_session: Session, election, delegate_keys) -> list[int]:
    """SR-08: Northgate with four candidates, published as a new signed definition version (fixture data)."""
    db_session.add(
        Candidate(
            election_id=election.election.id,
            division_id=election.divisions["Northgate"].id,
            given_name="Priya",
            surname="Natarajan",
            party="Civic Reform",
            ballot_position=4,
        )
    )
    db_session.commit()
    payload = build_payload(db_session, election.election, datetime(2000, 1, 1, tzinfo=UTC), datetime(2100, 1, 1, tzinfo=UTC))
    signatures = [sign(delegate_keys[d], payload) for d in ("delegate_a", "delegate_b")]
    store_active(db_session, election.election.id, payload, signatures, election.election.starts_at - timedelta(hours=25))
    db_session.commit()
    division = next(d for d in json.loads(payload)["divisions"] if d["name"] == "Northgate")
    return [c["candidate_id"] for c in division["candidates"]]


def open_ballot(client: TestClient, make_voter, sign_in) -> tuple[dict, object]:
    """A newly signed-in Northgate elector and their ballot."""
    client.post("/api/auth/logout")
    voter = make_voter(division="Northgate")
    sign_in(voter)
    return client.get("/api/ballot").json(), voter


def submit(client: TestClient, ballot: dict, ranking: list[int]):
    return client.post("/api/ballot/submit", json={"ballot_token": ballot["ballot_token"], "ranked_candidate_ids": ranking})


def outcome(response) -> tuple[int, dict]:
    return response.status_code, response.json()


def count(db_session: Session, model) -> int:
    db_session.expire_all()
    return db_session.scalar(select(func.count()).select_from(model))


def state_of(db_session: Session, voter) -> ParticipationState:
    db_session.expire_all()
    roll_id = db_session.get_one(Account, voter.account_id).roll_id
    return db_session.scalars(select(VoterParticipation.state).where(VoterParticipation.roll_id == roll_id)).one()


# ---------------------------------------------------------------
# The rules on their own
# ---------------------------------------------------------------


def test_every_candidate_ranked_is_formal_in_any_order() -> None:
    """SR-08 test 1 (rules): all four ranked, in several orders, is formal."""
    for ranking in ([A, B, C, D], [D, C, B, A], [C, A, D, B]):
        assert evaluate_house_ballot(FOUR, ranking) == FORMAL


@pytest.mark.parametrize(("ranking", "verdict"), [([A, B, C], INCOMPLETE), ([B, D], INCOMPLETE), ([C], INCOMPLETE), ([], BLANK)])
def test_fewer_than_every_candidate_is_informal(ranking: list[int], verdict: Verdict) -> None:
    """SR-08 test 2: three, two or one ranked is an incomplete order; none ranked is blank. No savings provision."""
    assert evaluate_house_ballot(FOUR, ranking) == verdict


@pytest.mark.parametrize(
    ("ranking", "reason"),
    [
        ([A, B, B, C], "duplicate_candidate"),
        ([A, B, C, 99], "invalid_candidate"),
        ([A, B, C, 21], "invalid_candidate"),  # a candidate of another division
        ([A, B, C, D, 99], "too_many"),
    ],
)
def test_impossible_rankings_are_invalid(ranking: list[int], reason: str) -> None:
    """SR-08 test 3: a repeated, unknown or other-division candidate, or five entries for four, is invalid."""
    assert evaluate_house_ballot(FOUR, ranking) == Verdict("invalid", reason)


def test_one_and_two_candidate_divisions() -> None:
    """SR-08 test 4: one candidate: [c] formal, [] informal. Two: [a, b] formal, [a] informal."""
    assert evaluate_house_ballot([C], [C]) == FORMAL
    assert evaluate_house_ballot([C], []) == BLANK
    assert evaluate_house_ballot([A, B], [A, B]) == FORMAL
    assert evaluate_house_ballot([A, B], [A]) == INCOMPLETE


def test_every_ranking_the_interface_can_produce_is_formal() -> None:
    """SR-08 test 7: the interface only submits complete orders, and all 24 orders of four candidates pass."""
    assert all(evaluate_house_ballot(FOUR, list(order)) == FORMAL for order in itertools.permutations(FOUR))


# ---------------------------------------------------------------
# Through the API
# ---------------------------------------------------------------


def test_formal_ballots_are_stored_in_the_submitted_order(
    client: TestClient, db_session: Session, northgate, make_voter, sign_in
) -> None:
    """SR-08 test 1 (API): all four ranked in different orders are accepted and stored exactly in that order."""
    orders = [northgate, northgate[::-1], [northgate[2], northgate[0], northgate[3], northgate[1]]]
    for order in orders:
        ballot, _ = open_ballot(client, make_voter, sign_in)
        assert [c["id"] for c in ballot["candidates"]] == northgate
        assert submit(client, ballot, order).status_code == 200

    # SR-11: the stored bytes are encrypted, so they are read back through decrypt_ballot
    stored = [decrypt_ballot(b.encrypted_payload, b.id, b.election_id)[RANKING_FIELD] for b in db_session.scalars(select(Ballot))]
    assert sorted(stored) == sorted(orders)


@pytest.mark.parametrize(
    ("make_ranking", "expected"),
    [
        (lambda ids: ids[:3], {"detail": "informal_ballot", "reason": "incomplete_order"}),
        (lambda ids: [], {"detail": "informal_ballot", "reason": "blank"}),
        (lambda ids: [*ids[:3], ids[0]], {"detail": "invalid_ballot"}),
        (lambda ids: [*ids, 999_999], {"detail": "invalid_ballot"}),
    ],
    ids=["incomplete", "blank", "repeated", "five entries"],
)
def test_a_refused_ballot_changes_nothing_and_can_be_corrected(
    client: TestClient, db_session: Session, northgate, make_voter, sign_in, make_ranking, expected: dict
) -> None:
    """SR-08 test 5: 422 with the expected body; token unused, elector still issued, no ballot; same token works after."""
    ballot, voter = open_ballot(client, make_voter, sign_in)

    assert outcome(submit(client, ballot, make_ranking(northgate))) == (422, expected)

    assert db_session.scalars(select(BallotToken.receipt_reference)).one() is None  # SR-12: still unused
    assert state_of(db_session, voter) == ParticipationState.ISSUED
    assert count(db_session, Ballot) == 0
    assert submit(client, ballot, northgate).status_code == 200
    assert state_of(db_session, voter) == ParticipationState.VOTED


def test_a_used_token_is_answered_before_any_rule_is_checked(
    client: TestClient, db_session: Session, northgate, make_voter, sign_in, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-08 test 6: SR-03 replay is unchanged: a used token gets its receipt, and no rule is evaluated."""
    ballot, _ = open_ballot(client, make_voter, sign_in)
    first = submit(client, ballot, northgate)

    def must_not_run(*_args):
        raise AssertionError("a replay must not be evaluated")

    monkeypatch.setattr(ballot_router, "evaluate_house_ballot", must_not_run)
    again = submit(client, ballot, [])

    assert outcome(again) == outcome(first) and first.status_code == 200
    assert count(db_session, Ballot) == 1


def test_invalid_requests_are_audited_and_informal_ones_are_not(
    client: TestClient, db_session: Session, northgate, make_voter, sign_in
) -> None:
    """SR-08 test 8: BALLOT_REJECTED_INVALID for an invalid request; nothing at all for an informal one."""
    ballot, voter = open_ballot(client, make_voter, sign_in)
    before = db_session.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))

    submit(client, ballot, northgate[:2])
    submit(client, ballot, [])
    assert db_session.scalar(select(func.max(AuditLogEntry.id))) == before

    submit(client, ballot, [northgate[0], northgate[0]])
    rows = db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.id > before)).all()
    assert [(r.event_type, r.actor, r.details) for r in rows] == [
        ("BALLOT_REJECTED_INVALID", f"account:{voter.account_id}", {})
    ]
