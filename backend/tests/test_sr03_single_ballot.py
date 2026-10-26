"""
SR-03: no more than one ballot per elector per election. A ballot token is
single use, 256 random bits, and is consumed in the same transaction that
stores the ballot. Replays and simultaneous duplicates add no ballot.
SR-12: a token has no stored expiry any more. It is usable while its election
is open and the elector is signed in.
SR-14: "used" is a flag, and the token keeps only the SHA-256 of the receipt it returned.
"""

import hashlib
import threading
import traceback
from collections.abc import Callable
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, inspect, select, text
from sqlalchemy.orm import Session

from helpers import CommittedDatabase, count, outcome, token_row
from app.config import settings
from app.db import Base
from app.main import app
from app.models import (
    Account,
    AuditLogEntry,
    AuthSession,
    BallotToken,
    ElectoralRollEntry,
    Election,
    ParticipationState,
    PendingBallot,  # VULN-01: an accepted ballot is held in pending_ballots until its seal
    SessionStage,
    VoterParticipation,
)
from app.routers import ballot as ballot_router
from app.security import SESSION_COOKIE, hash_token, new_token, utc_now
from scripts.seed import reset_participation, seed

SUBMIT = "/api/ballot/submit"
ALREADY_VOTED = (409, {"detail": "already_voted"})
INVALID = (400, {"detail": "invalid_ballot"})
# SR-12: a token is refused once the session or the election has ended, not after a stored expiry
SIGNED_OUT = (401, {"detail": "not_signed_in"})
CLOSED = (404, {"detail": "no_open_election"})


def submit(client: TestClient, ballot: dict, token: str | None = None, ranking: list[int] | None = None):
    return client.post(
        SUBMIT,
        json={
            "ballot_token": token or ballot["ballot_token"],
            "ranked_candidate_ids": ranking or [c["id"] for c in ballot["candidates"]],
        },
    )


def state_of(db_session: Session, voter, election) -> ParticipationState | None:
    db_session.expire_all()
    roll_id = db_session.get_one(Account, voter.account_id).roll_id
    row = db_session.get(VoterParticipation, (roll_id, election.election.id))
    return row.state if row else None


def unused(token: BallotToken) -> bool:
    # SR-14: not used, and no receipt hash recorded
    return (token.consumed, token.receipt_hash) == (False, None)


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
    assert count(db_session, PendingBallot) == 1
    assert state_of(db_session, voter, election) == ParticipationState.VOTED
    token = token_row(db_session, ballot["ballot_token"])
    # SR-14: used, and holding only the SHA-256 of the receipt it returned, never the receipt
    assert token.consumed and token.receipt_hash == hashlib.sha256(response.json()["receipt_id"].encode()).hexdigest()


def test_replayed_token_gets_the_first_answer_and_no_new_ballot(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-03 test 2: the same token again: the same status and receipt reference, and still one ballot."""
    sign_in(make_voter())
    ballot = client.get("/api/ballot").json()
    first = submit(client, ballot)

    again = [submit(client, ballot) for _ in range(3)]

    assert all(outcome(r) == outcome(first) for r in again) and first.status_code == 200
    assert count(db_session, PendingBallot) == 1


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


def test_token_lasts_while_the_session_and_the_election_do(
    client: TestClient, db_session: Session, election, make_voter, sign_in, clock
) -> None:
    """
    SR-03 test 6, SR-12: there is no stored token expiry. A token is accepted after 10 minutes while
    the session is extended, and refused, changing nothing, once the session or the election has ended.
    """
    late, signed_out, closed = make_voter(), make_voter(), make_voter()
    sign_in(late)
    ballot = client.get("/api/ballot").json()
    clock.advance(minutes=9)
    assert client.post("/api/auth/extend").status_code == 204
    clock.advance(minutes=9)
    assert submit(client, ballot).status_code == 200
    client.post("/api/auth/logout")

    refused = []
    sign_in(signed_out)
    after_session = client.get("/api/ballot").json()
    clock.advance(minutes=settings.session_minutes, seconds=1)
    refused.append((signed_out, after_session, submit(client, after_session), SIGNED_OUT))
    client.post("/api/auth/logout")

    sign_in(closed)
    after_close = client.get("/api/ballot").json()
    election.election.ends_at = clock.now
    db_session.commit()
    refused.append((closed, after_close, submit(client, after_close), CLOSED))

    for voter, paper, response, expected in refused:
        assert outcome(response) == expected
        assert state_of(db_session, voter, election) == ParticipationState.ISSUED
        assert unused(token_row(db_session, paper["ballot_token"]))
    assert count(db_session, PendingBallot) == 1


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
    assert count(db_session, PendingBallot) == 0
    assert state_of(db_session, voter, election) == ParticipationState.ISSUED
    assert unused(token_row(db_session, real))  # SR-12, SR-14: still unused
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
    # SR-12: no expiry or "used at" time on the token any more
    # SR-14: a used flag and the receipt hash replace the plaintext receipt reference
    assert columns["ballot_tokens"] == {"id", "election_id", "token_hash", "consumed", "receipt_hash"}
    # SR-11: the division and ranking now live only inside the encrypted payload
    assert columns["ballots"] == {"id", "election_id", "encrypted_payload"}
    for table in ("ballot_tokens", "ballots"):
        # SR-12: the ballot side has no foreign key at all
        assert schema.get_foreign_keys(table) == []
    assert {fk["referred_table"] for fk in schema.get_foreign_keys("voter_participation")} == {"electoral_roll", "elections"}
    assert "created_at" not in columns["ballot_tokens"] | columns["ballots"] | columns["voter_participation"]


def test_failure_while_storing_the_ballot_changes_nothing(
    client: TestClient, db_session: Session, election, make_voter, sign_in, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-03 test 9: the ballot INSERT fails, so the token stays unused and the elector is not marked voted."""
    voter = make_voter()
    sign_in(voter)
    ballot = client.get("/api/ballot").json()
    real_ballot = ballot_router.PendingBallot
    # A missing ciphertext makes the database refuse the INSERT (SR-11 removed the division column and
    # SR-12 the election foreign key, which earlier versions of this test broke instead)
    monkeypatch.setattr(ballot_router, "PendingBallot", lambda **fields: real_ballot(**(fields | {"encrypted_payload": None})))

    # SR-12: the error that reaches the server log carries none of the database's text about the row
    with pytest.raises(ballot_router.BallotStoreError) as failed:
        submit(client, ballot)
    assert str(failed.value) == "the accepted ballot could not be stored"
    # Everything a server log would print for it, causes and contexts included
    logged = "".join(traceback.format_exception(failed.value))
    assert not any(word in logged for word in ("IntegrityError", "NotNullViolation", "Failing row", "DETAIL"))

    assert count(db_session, PendingBallot) == 0
    assert state_of(db_session, voter, election) == ParticipationState.ISSUED
    assert unused(token_row(db_session, ballot["ballot_token"]))
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

    by_election = PendingBallot.election_id == election.election.id
    assert count(db_session, PendingBallot, by_election) == count(db_session, VoterParticipation, VOTED) == 4
    assert count(db_session, VoterParticipation, VoterParticipation.state == ParticipationState.ISSUED) == 1


def test_voted_elector_with_another_unused_token_is_refused(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-03 test 12: someone who has voted cannot use any other unused token either.
    VULN-05: the other token was issued to another session, so it is now refused before the voted
    check, with the generic invalid_ballot instead of already_voted; it still changes nothing."""
    first, second = make_voter(), make_voter()
    sign_in(second)
    other_ballot = client.get("/api/ballot").json()
    client.post("/api/auth/logout")
    sign_in(first)
    ballot = client.get("/api/ballot").json()
    assert submit(client, ballot).status_code == 200

    response = submit(client, ballot, token=other_ballot["ballot_token"])

    assert outcome(response) == (400, {"detail": "invalid_ballot"})
    assert count(db_session, PendingBallot) == 1
    assert unused(token_row(db_session, other_ballot["ballot_token"]))  # SR-12, SR-14: unused


def test_audit_events_hold_no_token_reference_or_ballot_content(
    client: TestClient, db_session: Session, make_voter, sign_in, clock, audit_text
) -> None:
    """SR-03 test 13: issue, accept, replay and each rejection are audited by account and event type only.
    SR-16: plus the allow-listed outcome and role, never a free-text field; every column is searched."""
    before = db_session.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))
    voted, late_voter, unissued = make_voter(), make_voter(), make_voter()

    sign_in(voted)
    ballot = client.get("/api/ballot").json()
    receipt = submit(client, ballot).json()["receipt_id"]
    submit(client, ballot)
    submit(client, ballot, token=new_token())
    client.post("/api/auth/logout")
    # SR-12: tokens no longer expire on their own, so this late ballot is accepted, not rejected
    sign_in(late_voter)
    late = client.get("/api/ballot").json()
    clock.advance(minutes=5)
    client.post("/api/auth/extend")
    clock.advance(minutes=5, seconds=1)
    late_receipt = submit(client, late).json()["receipt_id"]
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
    # VULN-05: the unissued elector presented another session's token: wrong_session, before the state check
    assert {r.reason for r in rows if r.event_type == "BALLOT_TOKEN_REJECTED"} == {"invalid", "wrong_session"}
    assert {r.actor for r in rows} == {f"account:{v.account_id}" for v in (voted, late_voter, unissued)}
    assert all(r.details is None and r.batch_no is None and r.count is None for r in rows)
    assert {r.category for r in rows} == {"eligibility"} and {r.role for r in rows} == {"elector"}
    recorded = audit_text(before)
    secrets = [
        ballot["ballot_token"],
        late["ballot_token"],
        receipt,
        late_receipt,
        hashlib.sha256(late["ballot_token"].encode()).hexdigest(),
    ]
    assert [s for s in secrets if s in recorded] == []


# ---------------------------------------------------------------
# The development reset
# ---------------------------------------------------------------


def test_reset_participation_clears_issued_and_refuses_voted(db_session: Session) -> None:
    """SR-03 test 14: the script clears an "issued" reviewer, audits it, and refuses a "voted" one.
    SR-16: the actor is now the script that did it (it was "unknown")."""
    seed(db_session)
    entry = db_session.scalars(select(ElectoralRollEntry)).one()
    election = db_session.scalars(select(Election)).one()
    assert reset_participation(db_session).endswith("Nothing to reset.")

    db_session.add(VoterParticipation(roll_id=entry.id, election_id=election.id, state=ParticipationState.ISSUED))
    db_session.commit()
    assert reset_participation(db_session).startswith("Cleared")
    assert count(db_session, VoterParticipation) == 0
    reset = db_session.scalars(select(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(1)).one()
    assert (reset.event_type, reset.actor, reset.role, reset.outcome, reset.details) == ("ELECTOR_RESET", "script", "script", "success", None)

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


class TestConcurrency(CommittedDatabase):
    """
    SR-03: real, separate transactions on threads. These tests replace the
    db_session and client fixtures with committing ones, so every factory
    commits for real, and they empty the test database afterwards.
    """

    def test_twenty_simultaneous_submissions_of_one_token_store_one_ballot(
        self, client: TestClient, db_session: Session, election, make_voter
    ) -> None:
        """SR-03 test 3: 20 submissions of the same token at once, in 3 rounds: exactly one ballot each round."""
        for round_number in range(1, 4):
            voter = make_voter()
            sessions = signed_in_sessions(db_session, voter, 20)
            ballot = as_voter(sessions[0]).get("/api/ballot").json()
            # VULN-05: the token works only in the session it was issued to, so every one of the 20
            # devices is given that session's binding, as if each had been issued it (separate
            # sessions still matter: see signed_in_sessions)
            db_session.execute(
                text(
                    "UPDATE sessions SET ballot_token_mac = (SELECT ballot_token_mac FROM sessions WHERE session_id_hash = :first) "
                    "WHERE account_id = :account"
                ),
                {"first": hash_token(sessions[0]), "account": voter.account_id},
            )
            db_session.commit()

            responses = run_together([lambda s=s: submit(as_voter(s), ballot) for s in sessions])

            assert [r.status_code for r in responses] == [200] * 20
            assert len({r.json()["receipt_id"] for r in responses}) == 1
            assert count(db_session, PendingBallot) == count(db_session, VoterParticipation, VOTED) == round_number

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
