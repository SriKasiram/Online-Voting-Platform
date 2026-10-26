"""
SR-14: after a ballot is durably accepted, the voter gets a confirmation within 10 seconds holding
only a 128-bit reference: no ballot content. The server stores only the reference's SHA-256.
"""

import hashlib
import logging
import re
import time

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from helpers import CommittedDatabase, count, state_of, token_row
from app.config import Settings, settings
from app.main import app
from app.models import Account, ParticipationState, PendingBallot  # VULN-01: an accepted ballot is held in pending_ballots until its seal
from app.routers import ballot as ballot_router
from app.security import SESSION_COOKIE
from scripts import audit_separation

SUBMIT = "/api/ballot/submit"
GENERIC_ERROR = (400, {"detail": "invalid_ballot"})


def expected_reference(token: str) -> str:
    """SR-14: the derivation, written out independently of the app's own function."""
    return hashlib.sha256(b"evoting-receipt-v1|" + token.encode()).digest()[:16].hex()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def open_paper(client: TestClient, make_voter, sign_in) -> tuple[dict, object]:
    voter = make_voter()
    sign_in(voter)
    return client.get("/api/ballot").json(), voter


def submit(client: TestClient, paper: dict, token: str | None = None):
    ranking = [c["id"] for c in reversed(paper["candidates"])]
    return client.post(SUBMIT, json={"ballot_token": token or paper["ballot_token"], "ranked_candidate_ids": ranking})


def rows_text(db: Session, *tables: str) -> str:
    return " ".join(row for table in tables for row in db.scalars(text(f'SELECT row_to_json(t)::text FROM "{table}" AS t')))


# ---------------------------------------------------------------
# The confirmation
# ---------------------------------------------------------------


def test_confirmation_comes_within_10_seconds_and_holds_only_the_reference(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-14 test 1: under 10 seconds; the body is exactly {"receipt_id"}; no ballot content, id, token or hash."""
    paper, _ = open_paper(client, make_voter, sign_in)

    started = time.perf_counter()
    response = submit(client, paper)
    elapsed = time.perf_counter() - started

    assert response.status_code == 200 and elapsed < 10
    assert list(response.json()) == ["receipt_id"]
    ballot_id = str(db_session.scalar(select(PendingBallot.id)))
    leaks = [ballot_id, paper["ballot_token"], hashlib.sha256(paper["ballot_token"].encode()).hexdigest(), paper["division_name"]]
    leaks += [part for c in paper["candidates"] for part in (c["given_name"], c["surname"], c["party"])]
    assert [leak for leak in leaks if leak in response.text] == []
    assert not re.search(r'"\d+"|\[\d', response.text)  # no candidate ids or ranking
    # SR-09 and SR-10 still apply to the confirmation
    assert response.headers["cache-control"] == "no-store" and "max-age" in response.headers["strict-transport-security"]


def test_reference_is_128_bits_derived_from_the_token(client: TestClient, make_voter, sign_in) -> None:
    """SR-14 test 2: 32 lowercase hex characters (16 bytes): the first 128 bits of SHA-256 over the tag and the token."""
    paper, _ = open_paper(client, make_voter, sign_in)

    reference = submit(client, paper).json()["receipt_id"]

    assert re.fullmatch(r"[0-9a-f]{32}", reference) and len(bytes.fromhex(reference)) == 16
    assert reference == expected_reference(paper["ballot_token"])


def test_only_the_reference_hash_is_stored(client: TestClient, db_session: Session, make_voter, sign_in) -> None:
    """SR-14 test 3: receipt_hash is the SHA-256 of the returned reference; the reference itself is stored nowhere."""
    paper, _ = open_paper(client, make_voter, sign_in)

    reference = submit(client, paper).json()["receipt_id"]

    token = token_row(db_session, paper["ballot_token"])
    assert token.consumed and token.receipt_hash == sha256_hex(reference)
    assert reference not in rows_text(db_session, "ballot_tokens", "ballots", "ballot_chain")


def test_retry_with_the_same_token_returns_the_same_reference(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-14 test 4: a retry recomputes the same reference from the token, and adds no ballot."""
    paper, _ = open_paper(client, make_voter, sign_in)
    first = submit(client, paper)

    again = [submit(client, paper) for _ in range(2)]

    assert [(r.status_code, r.json()) for r in again] == [(200, first.json())] * 2
    assert count(db_session, PendingBallot) == 1


def test_retry_with_a_modified_token_gets_the_generic_error(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-14 test 5: a token one character off is unknown: the generic error, and still one ballot."""
    paper, _ = open_paper(client, make_voter, sign_in)
    submit(client, paper)
    token = paper["ballot_token"]

    response = submit(client, paper, token=token[:-1] + ("A" if token[-1] != "A" else "B"))

    assert (response.status_code, response.json()) == GENERIC_ERROR
    assert count(db_session, PendingBallot) == 1


@pytest.mark.parametrize("stored", ["missing (used before SR-14)", "altered"])
def test_used_token_without_a_matching_receipt_hash_gets_the_generic_error(
    client: TestClient, db_session: Session, make_voter, sign_in, stored: str
) -> None:
    """SR-14 test 6: a used token whose stored hash is NULL or does not match: the generic error, nothing changes."""
    paper, voter = open_paper(client, make_voter, sign_in)
    submit(client, paper)
    value = None if stored.startswith("missing") else sha256_hex("not the reference")
    db_session.execute(
        text("UPDATE ballot_tokens SET receipt_hash = :h WHERE token_hash = :t"),
        {"h": value, "t": hashlib.sha256(paper["ballot_token"].encode()).hexdigest()},
    )
    db_session.commit()

    response = submit(client, paper)

    assert (response.status_code, response.json()) == GENERIC_ERROR
    assert "receipt_id" not in response.text
    token = token_row(db_session, paper["ballot_token"])
    assert (token.consumed, token.receipt_hash) == (True, value)
    assert count(db_session, PendingBallot) == 1 and state_of(db_session, voter) == ParticipationState.VOTED


def test_reference_and_hash_are_not_on_the_identity_side_or_in_logs(
    client: TestClient, db_session: Session, make_voter, sign_in, caplog: pytest.LogCaptureFixture
) -> None:
    """SR-14 test 7: neither the reference nor its hash is in participation, sessions, the audit log or any log line."""
    caplog.set_level(logging.DEBUG)
    paper, _ = open_paper(client, make_voter, sign_in)

    reference = submit(client, paper).json()["receipt_id"]
    submit(client, paper)  # a replay too

    stored = rows_text(db_session, "voter_participation", "sessions", "audit_log")
    assert "BALLOT_ACCEPTED" in stored and "BALLOT_REPLAY_BLOCKED" in stored
    for secret in (reference, sha256_hex(reference)):
        assert secret not in stored
        assert secret not in caplog.text


def test_failure_while_storing_returns_no_confirmation(
    client: TestClient, db_session: Session, make_voter, sign_in, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-14 test 8: the ballot INSERT fails (the SR-03 pattern): an error, no reference, and the token still unused."""
    paper, voter = open_paper(client, make_voter, sign_in)
    real_ballot = ballot_router.PendingBallot
    monkeypatch.setattr(ballot_router, "PendingBallot", lambda **fields: real_ballot(**(fields | {"encrypted_payload": None})))
    server = TestClient(app, base_url="https://testserver", raise_server_exceptions=False, cookies={SESSION_COOKIE: client.cookies[SESSION_COOKIE]})

    response = submit(server, paper)

    assert response.status_code == 500 and "receipt_id" not in response.text
    assert expected_reference(paper["ballot_token"]) not in response.text
    token = token_row(db_session, paper["ballot_token"])
    assert (token.consumed, token.receipt_hash) == (False, None)
    assert count(db_session, PendingBallot) == 0 and state_of(db_session, voter) == ParticipationState.ISSUED


def test_separation_audit_passes_and_covers_receipts(
    client: TestClient, db_session: Session, make_voter, sign_in, tmp_path, plant_audit_text
) -> None:
    """SR-14 test 9: SR-12's audit passes with receipt hashes, and catches the reference or its hash on the identity side.
    SR-16: the writer refuses both, so each is planted in the table directly."""
    paper, _ = open_paper(client, make_voter, sign_in)
    reference = submit(client, paper).json()["receipt_id"]

    assert {c.status for c in audit_separation.run_audit(db_session, [], tmp_path, tmp_path / "logs")} <= {"PASS", "SKIPPED"}
    identifiers = audit_separation.ballot_identifiers(db_session)
    assert sha256_hex(reference) in identifiers
    for leaked in (reference, sha256_hex(reference)):
        savepoint = db_session.begin_nested()
        plant_audit_text(leaked)
        assert audit_separation.check_identity_tables(db_session, identifiers).status == "FAIL"
        savepoint.rollback()


# ---------------------------------------------------------------
# The time limit
# ---------------------------------------------------------------


def test_timeout_setting_cannot_break_the_10_second_limit() -> None:
    """SR-14 test 10: ACCEPT_TIMEOUT_SECONDS is 8 by default and must be between 1 and 9."""
    assert Settings.model_fields["accept_timeout_seconds"].default == 8
    for invalid in (0, 10):
        with pytest.raises(ValidationError):
            Settings(accept_timeout_seconds=invalid)


@pytest.mark.parametrize(("sqlstate", "expected"), [("55P03", True), ("57014", True), ("23502", False), (None, False)])
def test_only_lock_and_statement_timeouts_count_as_timeouts(sqlstate: str | None, expected: bool) -> None:
    """SR-14 test 11: lock_timeout and statement_timeout get try_again; any other database error does not."""
    cause = type("Cause", (Exception,), {"sqlstate": sqlstate})()
    assert ballot_router.timed_out(OperationalError("statement", {}, cause)) is expected


class TestAcceptTimeout(CommittedDatabase):
    """
    SR-14: a real lock held by a second connection. Like SR-03's concurrency tests, these replace the
    db_session and client fixtures with committing ones (a second connection only sees committed
    rows), and empty the test database afterwards.
    """

    def test_locked_participation_row_gets_try_again_and_the_retry_works(
        self, client: TestClient, db_session: Session, engine: Engine, election, make_voter, sign_in, monkeypatch
    ) -> None:
        """SR-14 test 12: 503 try_again within 10 seconds, nothing stored; after the lock goes, the same token succeeds."""
        paper, voter = open_paper(client, make_voter, sign_in)
        roll_id = db_session.get_one(Account, voter.account_id).roll_id
        monkeypatch.setattr(settings, "accept_timeout_seconds", 1)

        with engine.connect() as locker, locker.begin():
            locker.execute(text("SELECT 1 FROM voter_participation WHERE roll_id = :r FOR UPDATE"), {"r": roll_id})
            started = time.perf_counter()
            blocked = submit(client, paper)
            elapsed = time.perf_counter() - started

        assert (blocked.status_code, blocked.json()) == (503, {"detail": "try_again"})
        assert 1 <= elapsed < 10
        token = token_row(db_session, paper["ballot_token"])
        assert (token.consumed, token.receipt_hash) == (False, None)
        assert count(db_session, PendingBallot) == 0 and state_of(db_session, voter) == ParticipationState.ISSUED

        retry = submit(client, paper)

        assert (retry.status_code, retry.json()) == (200, {"receipt_id": expected_reference(paper["ballot_token"])})
        assert count(db_session, PendingBallot) == 1 and state_of(db_session, voter) == ParticipationState.VOTED
