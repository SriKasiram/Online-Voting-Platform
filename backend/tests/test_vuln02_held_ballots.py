"""
VULN-02: before the seal, an accepted ballot is in no hash chain, so removing it went unnoticed by
the seal and by chain verification (only the count, at the very end, compared totals). The fix:
- the holding table's trigger refuses every UPDATE, and every DELETE unless the seal has already
  copied that exact ballot into ballots (no bypass flag);
- at every seal, every chain verification and before counting, the electors marked voted must
  equal the sealed plus held ballots (totals only, never a join), or it fails with
  ballot_count_mismatch and an SR-16 audit entry.
A database owner can still disable the trigger (the tests do, as an attacker with that role
would); the totals check is what catches it.
"""

import uuid
from contextlib import nullcontext

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from helpers import committed_triggers_off, triggers_off
from test_sr17_count import CountedElection
from app.audit_events import REASON_CODES
from app.ballot_chain import checkpoint_file, load_checkpoint_public_key, verify_chain
from app.models import AuditLogEntry
from scripts import verify_chain as verify_script
from scripts.seal_ballots import SealRefused, load_private_key, seal_batch

HELD = "pending_ballots"


@pytest.fixture
def keys(checkpoint_keys):
    private_path, public_path = checkpoint_keys
    return load_private_key(private_path), load_checkpoint_public_key(public_path)


def held_store(db: Session) -> str:
    """Where an accepted ballot waits for its seal: the holding table, or ballots before VULN-01."""
    return HELD if db.scalar(text(f"SELECT to_regclass('{HELD}') IS NOT NULL")) else "ballots"


def vote(client: TestClient, make_voter, sign_in, division: str = "Northgate") -> None:
    sign_in(make_voter(division=division))
    paper = client.get("/api/ballot").json()
    ranking = [candidate["id"] for candidate in paper["candidates"]]
    assert client.post("/api/ballot/submit", json={"ballot_token": paper["ballot_token"], "ranked_candidate_ids": ranking}).status_code == 200


def one_held_id(db: Session) -> uuid.UUID:
    return db.scalar(text(f"SELECT id FROM {held_store(db)} ORDER BY id LIMIT 1"))


def force_delete_one(db: Session) -> None:
    """VULN-02 attack: a database owner switches the trigger off and removes one held ballot."""
    store = held_store(db)
    with triggers_off(db, store):
        db.execute(text(f"DELETE FROM {store} WHERE id = :id"), {"id": one_held_id(db)})
    db.commit()


def failures(db: Session, event_type: str = "BALLOT_CHAIN_VERIFY_FAILED") -> list[AuditLogEntry]:
    db.expire_all()
    return list(db.scalars(select(AuditLogEntry).where(AuditLogEntry.event_type == event_type).order_by(AuditLogEntry.id)))


def allowed_fields_only(entry: AuditLogEntry) -> bool:
    # SR-16: a catalogued reason code and the script as actor; no details, batch, count or version
    return (entry.reason, entry.actor, entry.role, entry.outcome, entry.details, entry.batch_no, entry.count, entry.version) == (
        "ballot_count_mismatch", "script", "script", "failure", None, None, None, None,
    )


# ---------------------------------------------------------------
# The trigger
# ---------------------------------------------------------------


def test_deleting_a_held_ballot_is_blocked(client: TestClient, db_session: Session, make_voter, sign_in) -> None:
    """VULN-02 attack 1: a plain DELETE of a ballot waiting for its seal is refused by the holding table's trigger."""
    vote(client, make_voter, sign_in)
    held = db_session.scalar(text(f"SELECT id FROM {HELD}"))

    with pytest.raises(DBAPIError, match="DELETE on pending_ballots is not allowed"):
        with db_session.begin_nested():
            db_session.execute(text(f"DELETE FROM {HELD} WHERE id = :id"), {"id": held})

    assert db_session.scalar(text(f"SELECT count(*) FROM {HELD}")) == 1


def test_changing_a_held_ballot_is_blocked(client: TestClient, db_session: Session, make_voter, sign_in) -> None:
    """VULN-01, VULN-02: UPDATE on the holding table is always refused, whatever it changes."""
    vote(client, make_voter, sign_in)

    for change in ("encrypted_payload = encrypted_payload || '\\x00'::bytea", "election_id = gen_random_uuid()", "id = id"):
        with pytest.raises(DBAPIError, match="UPDATE on pending_ballots is not allowed"):
            with db_session.begin_nested():
                db_session.execute(text(f"UPDATE {HELD} SET {change}"))


def test_a_held_ballot_leaves_only_once_an_identical_copy_is_in_ballots(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """VULN-02: a copy with other bytes does not let the held ballot go; an identical copy (what the seal writes) does."""
    vote(client, make_voter, sign_in)
    ballot_id, election_id, blob = db_session.execute(text(f"SELECT id, election_id, encrypted_payload FROM {HELD}")).one()
    copy = text("INSERT INTO ballots (id, election_id, encrypted_payload) VALUES (:i, :e, :p)")
    delete = text(f"DELETE FROM {HELD} WHERE id = :i")

    with pytest.raises(DBAPIError, match="DELETE on pending_ballots is not allowed"):
        with db_session.begin_nested():
            db_session.execute(copy, {"i": ballot_id, "e": election_id, "p": bytes(blob) + b"\x00"})
            db_session.execute(delete, {"i": ballot_id})
    with db_session.begin_nested():
        db_session.execute(copy, {"i": ballot_id, "e": election_id, "p": blob})
        db_session.execute(delete, {"i": ballot_id})

    assert db_session.scalar(text(f"SELECT count(*) FROM {HELD}")) == 0


# ---------------------------------------------------------------
# A forced deletion is detected
# ---------------------------------------------------------------


def test_a_forced_deletion_makes_the_seal_refuse(
    client: TestClient, db_session: Session, election, make_voter, sign_in, keys, monkeypatch
) -> None:
    """VULN-02 attack 2: three voted, one held ballot removed with the trigger off: the seal refuses and audits why."""
    for _ in range(3):
        vote(client, make_voter, sign_in)
    election_id = election.election.id
    force_delete_one(db_session)

    with pytest.raises(SealRefused, match="ballot_count_mismatch"):
        seal_batch(db_session, election_id, True, *keys, checkpoint_file(election_id))

    assert db_session.scalar(text("SELECT count(*) FROM ballot_chain")) == 0
    [entry] = failures(db_session)
    assert allowed_fields_only(entry) and "ballot_count_mismatch" in REASON_CODES


def test_a_forced_deletion_fails_chain_verification(
    client: TestClient, db_session: Session, election, make_voter, sign_in, keys, monkeypatch, capsys
) -> None:
    """VULN-02 attack 3: the same removal makes verify_chain and python -m scripts.verify_chain fail, with an audit entry."""
    for _ in range(2):
        vote(client, make_voter, sign_in)
    election_id = election.election.id
    force_delete_one(db_session)
    monkeypatch.setattr(verify_script, "SessionLocal", lambda: nullcontext(db_session))

    assert verify_chain(db_session, election_id, keys[1], checkpoint_file(election_id)) == ["ballot_count_mismatch"]
    assert verify_script.main(["--election", str(election_id)]) == 1

    output = capsys.readouterr().out
    assert "FAIL     g. electors who voted = sealed + held ballots: ballot_count_mismatch" in output
    assert [allowed_fields_only(entry) for entry in failures(db_session)] == [True]


def test_ballot_stuffing_into_the_holding_table_is_detected(client: TestClient, db_session: Session, election, make_voter, sign_in, keys) -> None:
    """VULN-02: an extra held ballot with no elector behind it breaks the totals the other way."""
    vote(client, make_voter, sign_in)
    election_id = election.election.id
    db_session.execute(
        text(f"INSERT INTO {held_store(db_session)} (id, election_id, encrypted_payload) VALUES (gen_random_uuid(), :e, :p)"),
        {"e": election_id, "p": b"\x01" + bytes(60)},
    )
    db_session.commit()

    assert verify_chain(db_session, election_id, keys[1], checkpoint_file(election_id)) == ["ballot_count_mismatch"]


def test_the_totals_check_reads_totals_only(monkeypatch) -> None:
    """VULN-02, SR-12: three counts per election in one statement (one snapshot), never a join across the sides."""
    from app import ballot_chain

    sql = ballot_chain.BALLOT_TOTALS.text.upper()
    assert "JOIN" not in sql and sql.count("COUNT(*)") == 3


class TestBeforeCounting(CountedElection):
    """VULN-02: on a real, committed, sealed election (SR-17's five ballots, polls closed)."""

    def test_the_count_refuses_when_the_totals_disagree(self, engine: Engine, db_session: Session, sealed, keys) -> None:
        """VULN-02 attack 4: one more elector marked voted than ballots stored (a ballot removed before the seal)."""
        election_id = sealed["election_id"]
        db_session.execute(
            text("INSERT INTO voter_participation (roll_id, election_id, state) VALUES (:r, :e, 'voted')"),
            {"r": self.extra_roll_entry(db_session), "e": election_id},
        )
        db_session.commit()

        refused = self.refusal(engine, keys, election_id)

        assert (refused.code, refused.details) == ("chain_invalid", ["ballot_count_mismatch"])
        assert [allowed_fields_only(entry) for entry in failures(db_session)] == [True]

    def test_the_count_refuses_held_ballots_after_the_final_seal(self, engine: Engine, db_session: Session, sealed, keys) -> None:
        """VULN-01, SR-17: a ballot still held after the final seal is never counted, and stops the count."""
        election_id = sealed["election_id"]
        roll_id = self.extra_roll_entry(db_session)
        db_session.execute(text("INSERT INTO voter_participation (roll_id, election_id, state) VALUES (:r, :e, 'voted')"), {"r": roll_id, "e": election_id})
        db_session.execute(
            text(f"INSERT INTO {held_store(db_session)} (id, election_id, encrypted_payload) VALUES (gen_random_uuid(), :e, :p)"),
            {"e": election_id, "p": b"\x01" + bytes(60)},
        )
        db_session.commit()

        refused = self.refusal(engine, keys, election_id)

        assert (refused.code, refused.details) == ("chain_invalid", ["unsealed_after_final"])

    def test_a_forced_deletion_of_a_held_ballot_is_caught_on_committed_data(
        self, engine: Engine, db_session: Session, election, cast, keys, clock
    ) -> None:
        """VULN-02: removed with the trigger off and committed; the final seal still refuses, so nothing can be counted."""
        for order in ([0, 1, 2], [1, 2, 0]):
            cast("Northgate", order)
        clock.advance(days=2)
        election_id = election.election.id
        store = held_store(db_session)
        with committed_triggers_off(db_session, store):
            db_session.execute(text(f"DELETE FROM {store} WHERE id = :id"), {"id": one_held_id(db_session)})

        with pytest.raises(SealRefused, match="ballot_count_mismatch"):
            seal_batch(db_session, election_id, True, *keys, checkpoint_file(election_id))
        assert self.refusal(engine, keys, election_id).code == "no_final_checkpoint"

    def extra_roll_entry(self, db: Session) -> uuid.UUID:
        roll_id = uuid.uuid4()
        db.execute(
            text("INSERT INTO electoral_roll (id, roll_lookup, full_name_enc, address_enc, enrolled) VALUES (:i, :l, :n, :a, true)"),
            {"i": roll_id, "l": uuid.uuid4().bytes * 2, "n": b"x", "a": b"x"},
        )
        return roll_id
