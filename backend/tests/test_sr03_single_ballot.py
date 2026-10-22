"""
SR-03: no more than one ballot per elector per election. A ballot token is
single use, 256 random bits, expires BALLOT_TOKEN_MINUTES after issue, and is
consumed in the same transaction that stores the ballot. Replays and
simultaneous duplicates add no ballot.
"""

import hashlib
import json
import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Base
from app.deps import get_db
from app.main import app
from app.models import (
    Account,
    AuditLogEntry,
    AuthSession,
    Ballot,
    BallotToken,
    ElectoralRollEntry,
    Election,
    ParticipationState,
    SessionStage,
    VoterParticipation,
)
from app.routers import ballot as ballot_router
from app.security import SESSION_COOKIE, hash_token, new_token, utc_now
from scripts.seed import reset_participation, seed

SUBMIT = "/api/ballot/submit"
ALREADY_VOTED = (409, {"detail": "already_voted"})
INVALID = (400, {"detail": "invalid_ballot"})
EXPIRED = (400, {"detail": "ballot_expired"})


def submit(client: TestClient, ballot: dict, token: str | None = None, ranking: list[int] | None = None):
    return client.post(
        SUBMIT,
        json={
            "ballot_token": token or ballot["ballot_token"],
            "ranked_candidate_ids": ranking or [c["id"] for c in ballot["candidates"]],
        },
    )


def outcome(response) -> tuple[int, dict]:
    return response.status_code, response.json()


def count(db_session: Session, model, *where) -> int:
    db_session.expire_all()
    query = select(func.count()).select_from(model)
    return db_session.scalar(query.where(*where) if where else query)


def state_of(db_session: Session, voter, election) -> ParticipationState | None:
    db_session.expire_all()
    roll_id = db_session.get_one(Account, voter.account_id).roll_id
    row = db_session.get(VoterParticipation, (roll_id, election.election.id))
    return row.state if row else None


def token_row(db_session: Session, raw: str) -> BallotToken:
    db_session.expire_all()
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return db_session.scalars(select(BallotToken).where(BallotToken.token_hash == digest)).one()


VOTED = VoterParticipation.state == ParticipationState.VOTED


# ---------------------------------------------------------------
# Issue and accept
# ---------------------------------------------------------------


def test_valid_token_records_exactly_one_ballot(client: TestClient, db_session: Session, election, make_voter, sign_in) -> None:
    """SR-03 test 1: an eligible, signed-in elector's token stores one ballot and marks them voted."""
    voter = make_voter()
    sign_in(voter)
    ballot = client.get("/api/ballot").json()

    response = submit(client, ballot)

    assert response.status_code == 200
    assert count(db_session, Ballot) == 1
    assert state_of(db_session, voter, election) == ParticipationState.VOTED
    token = token_row(db_session, ballot["ballot_token"])
    assert token.consumed_at is not None and token.receipt_reference == response.json()["receipt_id"]


def test_replayed_token_gets_the_first_answer_and_no_new_ballot(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-03 test 2: the same token again: the same status and receipt reference, and still one ballot."""
    sign_in(make_voter())
    ballot = client.get("/api/ballot").json()
    first = submit(client, ballot)

    again = [submit(client, ballot) for _ in range(3)]

    assert all(outcome(r) == outcome(first) for r in again) and first.status_code == 200
    assert count(db_session, Ballot) == 1


def test_second_ballot_request_is_refused_after_issue_and_after_voting(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-03 test 5: a second ballot request, before or after voting, gets already_voted and no new token."""
    sign_in(make_voter())
    ballot = client.get("/api/ballot").json()

    assert outcome(client.get("/api/ballot")) == ALREADY_VOTED
    assert count(db_session, BallotToken) == 1
    assert submit(client, ballot).status_code == 200
    assert outcome(client.get("/api/ballot")) == ALREADY_VOTED
    assert count(db_session, BallotToken) == 1


def test_token_expires_ten_minutes_after_issue(
    client: TestClient, db_session: Session, election, make_voter, sign_in, clock
) -> None:
    """SR-03 test 6: accepted at 9 minutes 59 seconds after issue, rejected at 10 minutes 1 second."""
    assert settings.ballot_token_minutes == 10
    on_time, late = make_voter(), make_voter()
    sign_in(on_time)
    ballot = client.get("/api/ballot").json()
    clock.advance(minutes=9, seconds=59)
    assert submit(client, ballot).status_code == 200
    client.post("/api/auth/logout")

    sign_in(late)
    ballot = client.get("/api/ballot").json()
    # Keeping the session alive does not keep the token alive
    clock.advance(minutes=5)
    assert client.post("/api/auth/extend").status_code == 204
    clock.advance(minutes=5, seconds=1)
    response = submit(client, ballot)

    assert outcome(response) == EXPIRED
    assert count(db_session, Ballot) == 1
    assert state_of(db_session, late, election) == ParticipationState.ISSUED
    assert token_row(db_session, ballot["ballot_token"]).consumed_at is None


@pytest.mark.parametrize("kind", ["unknown", "tampered"])
def test_unknown_or_tampered_token_changes_nothing(
    client: TestClient, db_session: Session, election, make_voter, sign_in, kind: str
) -> None:
    """SR-03 test 7: a generic rejection, no ballot, the elector still issued and the real token still unused."""
    voter = make_voter()
    sign_in(voter)
    ballot = client.get("/api/ballot").json()
    real = ballot["ballot_token"]
    bad = new_token() if kind == "unknown" else real[:-1] + ("A" if real[-1] != "A" else "B")

    assert outcome(submit(client, ballot, token=bad)) == INVALID
    assert count(db_session, Ballot) == 0
    assert state_of(db_session, voter, election) == ParticipationState.ISSUED
    assert token_row(db_session, real).consumed_at is None
    assert submit(client, ballot).status_code == 200


def test_only_the_token_hash_is_stored_and_the_tables_share_no_link(
    engine: Engine, client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-03 test 8: the raw token is in no column anywhere, and the three tables hold nothing that links them."""
    sign_in(make_voter())
    ballot = client.get("/api/ballot").json()
    raw = ballot["ballot_token"]
    assert submit(client, ballot).status_code == 200

    # 32 random bytes, base64url encoded, and only its SHA-256 kept
    assert len(raw) == 43
    assert token_row(db_session, raw).token_hash == hashlib.sha256(raw.encode()).hexdigest()
    for table in Base.metadata.sorted_tables:
        found = db_session.scalar(
            text(f'SELECT count(*) FROM "{table.name}" AS row WHERE strpos(row::text, :raw) > 0'), {"raw": raw}
        )
        assert found == 0, table.name

    schema = inspect(engine)
    columns = {t: {c["name"] for c in schema.get_columns(t)} for t in ("voter_participation", "ballot_tokens", "ballots")}
    assert columns["voter_participation"] == {"roll_id", "election_id", "state"}
    assert columns["ballot_tokens"] == {"id", "election_id", "token_hash", "expires_at", "consumed_at", "receipt_reference"}
    # SR-11: the division and ranking now live only inside the encrypted payload
    assert columns["ballots"] == {"id", "election_id", "encrypted_payload"}
    for table in ("ballot_tokens", "ballots"):
        referenced = {fk["referred_table"] for fk in schema.get_foreign_keys(table)}
        assert referenced <= {"elections", "divisions"}
    assert {fk["referred_table"] for fk in schema.get_foreign_keys("voter_participation")} == {"electoral_roll", "elections"}
    assert "created_at" not in columns["ballot_tokens"] | columns["ballots"] | columns["voter_participation"]


def test_failure_while_storing_the_ballot_changes_nothing(
    client: TestClient, db_session: Session, election, make_voter, sign_in, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-03 test 9: the ballot INSERT fails, so the token stays unused and the elector is not marked voted."""
    voter = make_voter()
    sign_in(voter)
    ballot = client.get("/api/ballot").json()
    real_ballot = ballot_router.Ballot
    # An election that does not exist makes the database refuse the INSERT
    # (SR-11: ballots no longer have a division column to break instead)
    monkeypatch.setattr(ballot_router, "Ballot", lambda **fields: real_ballot(**(fields | {"election_id": uuid.uuid4()})))

    with pytest.raises(IntegrityError):
        submit(client, ballot)

    assert count(db_session, Ballot) == 0
    assert state_of(db_session, voter, election) == ParticipationState.ISSUED
    token = token_row(db_session, ballot["ballot_token"])
    assert (token.consumed_at, token.receipt_reference) == (None, None)
    monkeypatch.undo()
    assert submit(client, ballot).status_code == 200


@pytest.mark.parametrize("session", ["none", "waiting for the code"])
def test_ballot_routes_need_a_signed_in_session(
    client: TestClient, db_session: Session, make_voter, session: str
) -> None:
    """SR-03 test 10: no session, or one that has only passed the password step: 401, and nothing is issued."""
    voter = make_voter()
    if session != "none":
        client.post("/api/auth/login", json={"username": voter.username, "password": voter.password})

    assert client.get("/api/ballot").status_code == 401
    assert client.post(SUBMIT, json={"ballot_token": new_token(), "ranked_candidate_ids": [1]}).status_code == 401
    assert count(db_session, BallotToken) == count(db_session, VoterParticipation) == 0


def test_ballots_always_equal_voted_electors(
    client: TestClient, db_session: Session, election, make_voter, sign_in
) -> None:
    """SR-03 test 11: after votes, replays, rejections and unused tokens, ballots equal "voted" rows."""
    voters = [make_voter() for _ in range(5)]
    for number, voter in enumerate(voters):
        sign_in(voter)
        ballot = client.get("/api/ballot").json()
        if number == 1:
            submit(client, ballot)
            submit(client, ballot)  # a replay
        elif number == 2:
            pass  # issued and never used
        elif number == 3:
            submit(client, ballot, ranking=[c["id"] for c in ballot["candidates"]][:-1])  # rejected content
            submit(client, ballot)
        elif number == 4:
            submit(client, ballot, token=new_token())  # unknown token
            submit(client, ballot)
        else:
            submit(client, ballot)
        client.post("/api/auth/logout")

    by_election = Ballot.election_id == election.election.id
    assert count(db_session, Ballot, by_election) == count(db_session, VoterParticipation, VOTED) == 4
    assert count(db_session, VoterParticipation, VoterParticipation.state == ParticipationState.ISSUED) == 1


def test_voted_elector_with_another_unused_token_is_refused(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-03 test 12: someone who has voted cannot use any other unused token either."""
    first, second = make_voter(), make_voter()
    sign_in(second)
    other_ballot = client.get("/api/ballot").json()
    client.post("/api/auth/logout")
    sign_in(first)
    ballot = client.get("/api/ballot").json()
    assert submit(client, ballot).status_code == 200

    response = submit(client, ballot, token=other_ballot["ballot_token"])

    assert outcome(response) == ALREADY_VOTED
    assert count(db_session, Ballot) == 1
    assert token_row(db_session, other_ballot["ballot_token"]).consumed_at is None


def test_audit_events_hold_no_token_reference_or_ballot_content(
    client: TestClient, db_session: Session, make_voter, sign_in, clock
) -> None:
    """SR-03 test 13: issue, accept, replay and each rejection are audited by account and event type only."""
    before = db_session.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))
    voted, expired, unissued = make_voter(), make_voter(), make_voter()

    sign_in(voted)
    ballot = client.get("/api/ballot").json()
    receipt = submit(client, ballot).json()["receipt_id"]
    submit(client, ballot)
    submit(client, ballot, token=new_token())
    client.post("/api/auth/logout")
    sign_in(expired)
    late = client.get("/api/ballot").json()
    clock.advance(minutes=5)
    client.post("/api/auth/extend")
    clock.advance(minutes=5, seconds=1)
    submit(client, late)
    client.post("/api/auth/logout")
    sign_in(unissued)
    submit(client, late)

    rows = db_session.scalars(
        select(AuditLogEntry).where(AuditLogEntry.id > before, AuditLogEntry.event_type.like("BALLOT_%"))
    ).all()
    assert {r.event_type for r in rows} == {
        "BALLOT_TOKEN_ISSUED",
        "BALLOT_ACCEPTED",
        "BALLOT_REPLAY_BLOCKED",
        "BALLOT_TOKEN_REJECTED",
    }
    assert {r.details.get("reason") for r in rows if r.event_type == "BALLOT_TOKEN_REJECTED"} == {
        "invalid",
        "expired",
        "wrong_state",
    }
    assert {r.actor for r in rows} == {f"account:{v.account_id}" for v in (voted, expired, unissued)}
    assert all(set(r.details) <= {"reason"} for r in rows)
    recorded = json.dumps([[r.event_type, r.actor, r.details] for r in rows])
    secrets = [ballot["ballot_token"], late["ballot_token"], receipt, hashlib.sha256(late["ballot_token"].encode()).hexdigest()]
    assert [s for s in secrets if s in recorded] == []


# ---------------------------------------------------------------
# The development reset
# ---------------------------------------------------------------


def test_reset_participation_clears_issued_and_refuses_voted(db_session: Session) -> None:
    """SR-03 test 14: the script clears an "issued" reviewer, audits it, and refuses a "voted" one."""
    seed(db_session)
    entry = db_session.scalars(select(ElectoralRollEntry)).one()
    election = db_session.scalars(select(Election)).one()
    assert reset_participation(db_session).endswith("Nothing to reset.")

    db_session.add(VoterParticipation(roll_id=entry.id, election_id=election.id, state=ParticipationState.ISSUED))
    db_session.commit()
    assert reset_participation(db_session).startswith("Cleared")
    assert count(db_session, VoterParticipation) == 0
    reset = db_session.scalars(select(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(1)).one()
    assert (reset.event_type, reset.actor, reset.details) == ("ELECTOR_RESET", "unknown", {})

    db_session.add(VoterParticipation(roll_id=entry.id, election_id=election.id, state=ParticipationState.VOTED))
    db_session.commit()
    with pytest.raises(SystemExit, match="cannot be undone"):
        reset_participation(db_session)
    assert count(db_session, VoterParticipation, VOTED) == 1


# ---------------------------------------------------------------
# Real concurrency
# ---------------------------------------------------------------


def run_together(calls: list[Callable[[], object]]) -> list:
    """Starts every call at the same moment, each on its own thread."""
    barrier = threading.Barrier(len(calls))
    results: list = [None] * len(calls)

    def worker(index: int, call: Callable[[], object]) -> None:
        barrier.wait()
        results[index] = call()

    threads = [threading.Thread(target=worker, args=(i, call)) for i, call in enumerate(calls)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def as_voter(cookie: str) -> TestClient:
    return TestClient(app, base_url="https://testserver", headers={"cookie": f"{SESSION_COOKIE}={cookie}"})


def signed_in_sessions(db_session: Session, voter, count: int) -> list[str]:
    """
    One elector signed in on `count` devices at once. Separate sessions matter:
    requests on one session queue behind each other on its last_seen update, which
    would hide a race that the SR-03 locks must handle themselves.
    """
    tokens = [new_token() for _ in range(count)]
    db_session.add_all(
        AuthSession(
            session_id_hash=hash_token(token),
            account_id=voter.account_id,
            stage=SessionStage.AUTHENTICATED,
            expires_at=utc_now() + timedelta(minutes=settings.session_minutes),
        )
        for token in tokens
    )
    db_session.commit()
    return tokens


class TestConcurrency:
    """
    SR-03: real, separate transactions on threads. These tests replace the
    db_session and client fixtures with committing ones, so every factory
    commits for real, and they empty the test database afterwards.
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

    def test_twenty_simultaneous_submissions_of_one_token_store_one_ballot(
        self, client: TestClient, db_session: Session, election, make_voter
    ) -> None:
        """SR-03 test 3: 20 submissions of the same token at once, in 3 rounds: exactly one ballot each round."""
        for round_number in range(1, 4):
            sessions = signed_in_sessions(db_session, make_voter(), 20)
            ballot = as_voter(sessions[0]).get("/api/ballot").json()

            responses = run_together([lambda s=s: submit(as_voter(s), ballot) for s in sessions])

            assert [r.status_code for r in responses] == [200] * 20
            assert len({r.json()["receipt_id"] for r in responses}) == 1
            assert count(db_session, Ballot) == count(db_session, VoterParticipation, VOTED) == round_number

    def test_simultaneous_ballot_requests_issue_one_token(
        self, client: TestClient, db_session: Session, election, make_voter
    ) -> None:
        """SR-03 test 4: 20 ballot requests from one elector at once, in 3 rounds: one succeeds, one token exists."""
        for round_number in range(1, 4):
            sessions = signed_in_sessions(db_session, make_voter(), 20)

            responses = run_together([lambda s=s: as_voter(s).get("/api/ballot") for s in sessions])

            assert sorted(r.status_code for r in responses) == [200] + [409] * 19
            assert all(outcome(r) == ALREADY_VOTED for r in responses if r.status_code == 409)
            assert count(db_session, BallotToken) == count(db_session, VoterParticipation) == round_number
