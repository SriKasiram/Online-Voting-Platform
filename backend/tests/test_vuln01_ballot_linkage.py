"""
VULN-01: a stored ballot could be linked to the elector who cast it through PostgreSQL's system
columns. The ballot row was written in the same transaction as the elector's participation update,
their session update and the BALLOT_ACCEPTED audit entry, so all of them had the same xmin; and its
physical position (ctid) followed the order ballots arrived in.

The fix: acceptance writes the ballot to pending_ballots (the holding table). Each SR-13 seal copies
its batch into ballots in ballot id order, in a subtransaction of its own, deletes the held rows,
and the seal script then runs VACUUM FULL pending_ballots, so no dead row with the acceptance xmin
is left behind.

These are the attacks, run as a database reader would run them, on real committed transactions.
"""

import uuid
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from test_sr17_count import CountedElection
# SR-20's restore database, an empty database of its own for the migration test
from test_sr20_backup import restore_url, target, target_engine  # noqa: F401
from app.routers import ballot as ballot_router
from app.stores import BALLOT_TABLES, IDENTITY_TABLES
from scripts import audit_ballots, audit_separation, seal_ballots

HELD = "pending_ballots"


def xmin_links(db: Session, election_id: uuid.UUID, table: str = "ballots") -> dict[str, int]:
    """VULN-01 attack: for each identity-side table, how many of the election's ballots share a row's xmin."""
    db.rollback()
    return {
        identity: db.scalar(
            text(f'SELECT count(*) FROM "{table}" b JOIN "{identity}" t ON t.xmin::text = b.xmin::text WHERE b.election_id = :e'),
            {"e": election_id},
        )
        for identity in sorted(IDENTITY_TABLES)
    }


def physical_order(db: Session, election_id: uuid.UUID) -> list[uuid.UUID]:
    """VULN-01 attack: the election's sealed ballots in the order they sit on disk."""
    db.rollback()
    return list(db.scalars(text("SELECT id FROM ballots WHERE election_id = :e ORDER BY ctid"), {"e": election_id}))


def seal_by_script(db: Session, engine: Engine, monkeypatch: pytest.MonkeyPatch, election_id: uuid.UUID) -> int:
    """VULN-01: the returning officer's command, python -m scripts.seal_ballots --final, on the test database."""
    monkeypatch.setattr(seal_ballots, "SessionLocal", lambda: nullcontext(db))
    # the VACUUM step runs on the test database, never the development one
    monkeypatch.setattr(seal_ballots, "engine", engine, raising=False)
    return seal_ballots.main(["--election", str(election_id), "--final"])


class TestBallotLinkage(CountedElection):
    """VULN-01: the xmin join and the ctid order, before and after a seal."""

    @pytest.fixture
    def arrivals(self, monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
        """Ballot ids handed out in descending order, so the order of arrival is the reverse of id order."""
        handed_out: list[uuid.UUID] = []

        def next_id() -> uuid.UUID:
            handed_out.append(uuid.UUID(int=(0xF0 - len(handed_out)) << 120, version=4))
            return handed_out[-1]

        monkeypatch.setattr(ballot_router, "uuid", SimpleNamespace(uuid4=next_id))
        return handed_out

    @pytest.fixture
    def four_cast(self, election, cast, arrivals) -> list[uuid.UUID]:
        for order in ([0, 1, 2], [1, 2, 0], [2, 0, 1], [0, 2, 1]):
            cast("Northgate", order)
        return list(arrivals)

    def test_after_a_seal_no_ballot_shares_an_xmin_with_an_identity_row(
        self, engine: Engine, db_session: Session, election, four_cast, monkeypatch
    ) -> None:
        """VULN-01 attack 1: joining ballots to every identity-side table on xmin finds nothing after the seal."""
        election_id = election.election.id

        assert seal_by_script(db_session, engine, monkeypatch, election_id) == 0

        assert xmin_links(db_session, election_id) == dict.fromkeys(sorted(IDENTITY_TABLES), 0)
        assert db_session.scalar(text("SELECT count(*) FROM ballots WHERE election_id = :e"), {"e": election_id}) == 4

    def test_after_a_seal_the_disk_order_is_ballot_id_order_not_arrival(
        self, engine: Engine, db_session: Session, election, four_cast, monkeypatch
    ) -> None:
        """VULN-01 attack 2: ordering the sealed ballots by ctid gives ballot id order, never the order they arrived in."""
        election_id = election.election.id
        assert four_cast == sorted(four_cast, reverse=True)  # they arrived in descending id order

        seal_by_script(db_session, engine, monkeypatch, election_id)

        assert physical_order(db_session, election_id) == sorted(four_cast)

    def test_a_sealed_batch_shares_one_xmin_so_arrival_time_is_not_recoverable(
        self, engine: Engine, db_session: Session, election, four_cast, monkeypatch
    ) -> None:
        """VULN-01 attack 3: transaction ids grow with time; one xmin for the whole batch says nothing about when each arrived."""
        election_id = election.election.id

        seal_by_script(db_session, engine, monkeypatch, election_id)

        db_session.rollback()
        assert db_session.scalar(text("SELECT count(DISTINCT xmin::text) FROM ballots WHERE election_id = :e"), {"e": election_id}) == 1

    def test_the_holding_table_is_empty_on_disk_after_the_seal(
        self, engine: Engine, db_session: Session, election, four_cast, monkeypatch
    ) -> None:
        """VULN-01: the deleted held rows (with their acceptance xmin) are gone from disk too: VACUUM FULL left no page."""
        election_id = election.election.id

        seal_by_script(db_session, engine, monkeypatch, election_id)

        db_session.rollback()
        assert db_session.scalar(text(f"SELECT count(*) FROM {HELD}")) == 0
        assert db_session.scalar(text(f"SELECT pg_relation_size('{HELD}')")) == 0

    def test_held_ballots_stay_linkable_until_the_seal(self, db_session: Session, election, four_cast) -> None:
        """VULN-01 residual risk, shown: before the seal a held ballot still shares an xmin with its elector's rows."""
        links = xmin_links(db_session, election.election.id, HELD)

        assert links["voter_participation"] == 4 and links["audit_log"] == 4

    def test_the_audits_pass_after_the_seal(
        self, engine: Engine, db_session: Session, election, four_cast, monkeypatch, tmp_path: Path
    ) -> None:
        """VULN-01: after the seal the SR-11 audit and the SR-12 audit, with its new system column check, all pass."""
        seal_by_script(db_session, engine, monkeypatch, election.election.id)
        db_session.rollback()

        separation = {check.name: check for check in audit_separation.run_audit(db_session, [], tmp_path, tmp_path / "logs")}

        assert separation["f. system columns"].status == "PASS"
        assert {check.status for check in separation.values()} <= {"PASS", "SKIPPED"}
        assert {check.status for check in audit_ballots.run_audit(db_session, tmp_path)} <= {"PASS", "SKIPPED"}


# ---------------------------------------------------------------
# The SR-12 audit's system column check, on planted links
# ---------------------------------------------------------------


def system_column_check(db: Session, tmp_path: Path):
    checks = {check.name: check for check in audit_separation.run_audit(db, [], tmp_path, tmp_path / "logs")}
    return checks["f. system columns"]


def plant_ballot(db: Session, election_id: uuid.UUID, ballot_id: uuid.UUID) -> None:
    db.execute(
        text("INSERT INTO ballots (id, election_id, encrypted_payload) VALUES (:i, :e, :p)"),
        {"i": ballot_id, "e": election_id, "p": b"\x01" + bytes(60)},
    )


def test_the_holding_table_is_registered_on_the_ballot_side() -> None:
    """VULN-01, SR-12: pending_ballots holds ballots, so it is on the ballot side of the registry."""
    assert HELD in BALLOT_TABLES and HELD not in IDENTITY_TABLES


def test_the_system_column_check_fails_on_a_ballot_written_with_an_identity_row(db_session: Session, election, tmp_path: Path) -> None:
    """VULN-01: a ballot and an identity-side row written in one transaction share an xmin; the audit must fail."""
    election_id = election.election.id
    plant_ballot(db_session, election_id, uuid.uuid4())
    db_session.execute(text("UPDATE elections SET name = name WHERE id = :e"), {"e": election_id})

    check = system_column_check(db_session, tmp_path)

    assert check.status == "FAIL" and "xmin" in check.reason and "elections" in check.reason


def test_the_system_column_check_fails_on_a_disk_order_that_is_not_ballot_id_order(db_session: Session, election, tmp_path: Path) -> None:
    """VULN-01: ballots stored out of ballot id order could replay arrival; the audit must fail."""
    for ballot_id in sorted((uuid.uuid4() for _ in range(3)), reverse=True):
        plant_ballot(db_session, election.election.id, ballot_id)
    db_session.commit()

    check = system_column_check(db_session, tmp_path)

    assert check.status == "FAIL" and "disk order" in check.reason


def test_the_migration_moves_unsealed_ballots_to_the_holding_table(target_engine: Engine, alembic_config: Config) -> None:  # noqa: F811
    """VULN-01: upgrading to 0015 moves each unsealed ballot, unchanged, to pending_ballots; sealed ones stay. And back."""
    election_id, sealed, unsealed = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    earlier = alembic_config.attributes.get("connection")
    stores = "SELECT 'ballots', id, encrypted_payload FROM ballots UNION ALL SELECT 'pending_ballots', id, encrypted_payload FROM pending_ballots"
    try:
        with target_engine.begin() as connection:
            alembic_config.attributes["connection"] = connection
            command.upgrade(alembic_config, "0014")
            for ballot_id, payload in ((sealed, b"sealed"), (unsealed, b"unsealed")):
                connection.execute(
                    text("INSERT INTO ballots (id, election_id, encrypted_payload) VALUES (:i, :e, :p)"), {"i": ballot_id, "e": election_id, "p": payload}
                )
            connection.execute(
                text("INSERT INTO ballot_chain (election_id, position, batch_no, ballot_id, prev_hash, entry_hash) VALUES (:e, 1, 1, :i, 'a', 'b')"),
                {"e": election_id, "i": sealed},
            )

            command.upgrade(alembic_config, "0015")
            moved = sorted(tuple(row) for row in connection.execute(text(stores)))
            trigger = connection.scalar(text("SELECT tgenabled FROM pg_trigger WHERE tgname = 'ballots_append_only'"))
            command.downgrade(alembic_config, "0014")
            back = sorted(tuple(row) for row in connection.execute(text("SELECT 'ballots', id, encrypted_payload FROM ballots")))
    finally:
        alembic_config.attributes["connection"] = earlier

    assert moved == sorted([("ballots", sealed, b"sealed"), ("pending_ballots", unsealed, b"unsealed")])
    assert trigger == "O"  # SR-13's trigger on ballots is on again after the move
    assert back == sorted([("ballots", sealed, b"sealed"), ("ballots", unsealed, b"unsealed")])
