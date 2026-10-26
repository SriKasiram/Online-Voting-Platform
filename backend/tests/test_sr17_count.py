"""
SR-17: the House count uses only ballots from the verified chain up to the final signed checkpoint,
each decrypted with its own record binding and checked against the active signed definition, and
stops at the first failed check. Unsealed, altered, injected and invalid ballots never enter it.
"""

import json
import logging
import random
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from helpers import committed_triggers_off as triggers_off, CommittedDatabase
from app import house_count
from app.ballot_chain import checkpoint_file, compute_entry_hash, load_checkpoint_public_key, verify_chain
from app.ballot_crypto import ballot_payload, encrypt_ballot
from app.config import settings
from app.house_count import CountRefused, Round, break_tie, check_ballot, count_division, run_count
from app.models import AuditLogEntry, BallotChainEntry, ParticipationState, VoterParticipation
from app.security import AUDIT_FORMAT_CURRENT, audit_hash_at
from scripts import audit_ballots, audit_checkpoint, audit_separation, count_house, verify_audit
from scripts.seal_ballots import append_checkpoint, load_private_key, seal_batch

A, B, C, D = 1, 2, 3, 4


# ---------------------------------------------------------------
# The calculation (pure)
# ---------------------------------------------------------------


def test_majority_in_the_first_round() -> None:
    """SR-17: more than half of the formal ballots in round 1 elects at once; nobody is excluded."""
    result = count_division([A, B, C], [[A, B, C]] * 3 + [[B, A, C]] + [[C, B, A]])

    assert (result.status, result.elected, result.formal_total) == ("elected", A, 5)
    assert result.rounds == (Round({A: 3, B: 1, C: 1}, None),)


def test_several_rounds_with_transfers_match_the_hand_worked_example() -> None:
    """
    SR-17: three rounds, checked against this hand-worked count.

    Candidates A, B, C, D. 10 formal ballots, so more than half is 6 or more.
        4 x  A B C D
        3 x  B C A D
        2 x  C A B D
        1 x  D B C A
    Round 1: A 4, B 3, C 2, D 1. Nobody has 6. D has the fewest and is excluded;
             D's ballot goes to its next continuing choice, B.
    Round 2: A 4, B 4, C 2. Nobody has 6. C is excluded; both C ballots go to A.
    Round 3: A 6, B 4. A has 6 of 10, more than half: A is elected.
    Each round's total stays 10.
    """
    rankings = [[A, B, C, D]] * 4 + [[B, C, A, D]] * 3 + [[C, A, B, D]] * 2 + [[D, B, C, A]]

    result = count_division([A, B, C, D], rankings)

    assert result.rounds == (
        Round({A: 4, B: 3, C: 2, D: 1}, D),
        Round({A: 4, B: 4, C: 2}, C),
        Round({A: 6, B: 4}, None),
    )
    assert (result.status, result.elected) == ("elected", A)


def test_an_exclusion_tie_is_broken_by_an_earlier_round() -> None:
    """
    SR-17: B and C tie on the fewest votes in round 2; in round 1 C had fewer, so C is excluded.
        5 x A B C D,  3 x B A C D,  2 x C B A D,  1 x D C B A   (11 ballots, 6 elects)
    Round 1: A 5, B 3, C 2, D 1  -> D excluded, its ballot to C
    Round 2: A 5, B 3, C 3       -> B and C tied; round 1 had B 3, C 2, so C is excluded
    Round 3: A 5, B 6            -> B elected
    """
    rankings = [[A, B, C, D]] * 5 + [[B, A, C, D]] * 3 + [[C, B, A, D]] * 2 + [[D, C, B, A]]

    result = count_division([A, B, C, D], rankings)

    assert [r.excluded for r in result.rounds] == [D, C, None]
    assert result.rounds[-1].totals == {A: 5, B: 6} and result.elected == B


def test_a_three_way_tie_keeps_looking_back_among_those_still_tied() -> None:
    """SR-17: round 2 separates only C from A and B; round 1 then separates A and B, so B goes."""
    rounds = [Round({A: 4, B: 3, C: 6}, None), Round({A: 5, B: 5, C: 7}, None)]

    assert break_tie([A, B, C], rounds) == B


@pytest.mark.parametrize(
    "rankings",
    [
        [[A, B, C]] * 2 + [[B, A, C]] + [[C, A, B]],  # A 2 of 4 is no majority; B and C tie in round 1
        [[A, B, C, D]] * 2 + [[B, A, C, D]] + [[C, A, B, D]],  # D (0) goes; B and C were equal in round 1 too
        [[A, B]] * 2 + [[B, A]] * 2,  # an even split between the last two
    ],
    ids=["first round", "every round equal", "even split"],
)
def test_a_tie_no_earlier_round_separates_stops_the_count(rankings) -> None:
    """SR-17: no earlier round separates the tied candidates, so the count stops with unresolved_tie."""
    with pytest.raises(CountRefused) as refused:
        count_division(sorted(rankings[0]), rankings)

    assert refused.value.code == "unresolved_tie"


def test_one_candidate_and_a_division_with_no_ballots() -> None:
    """SR-17: a lone candidate is elected with every formal ballot; no ballots means no_ballots, no winner."""
    alone = count_division([7], [[7]] * 3)
    empty = count_division([A, B, C], [])

    assert (alone.status, alone.elected, alone.rounds) == ("elected", 7, (Round({7: 3}, None),))
    assert (empty.status, empty.elected, empty.formal_total, empty.rounds) == ("no_ballots", None, 0, ())


def test_same_input_same_result_and_round_totals_never_change() -> None:
    """SR-17: repeated runs, and the ballots in any order, give the same result; every round adds up."""
    candidates = [A, B, C, D]
    rankings = ([[A, B, C, D]] * 4 + [[B, C, A, D]] * 3 + [[C, A, B, D]] * 2 + [[D, B, C, A]]) * 7
    shuffled = rankings[:]
    random.Random(17).shuffle(shuffled)

    first = count_division(candidates, rankings)

    assert count_division(candidates, rankings) == first == count_division(candidates, shuffled)
    assert len(first.rounds) == 3 and all(sum(r.totals.values()) == 70 for r in first.rounds)


def test_a_ballot_that_would_exhaust_stops_the_count() -> None:
    """SR-17: an incomplete ranking would change a round's total, so the count stops rather than drop it."""
    with pytest.raises(CountRefused) as refused:
        # Round 1: A 2, B 2, C 1. C goes, and its only ballot has no next choice: round 2 would hold 4, not 5
        count_division([A, B, C], [[A, B, C]] * 2 + [[B, A, C]] * 2 + [[C]])

    assert refused.value.code == "informal_or_invalid"


# ---------------------------------------------------------------
# A real election: committed data, a second connection for the count
# ---------------------------------------------------------------


class CountedElection(CommittedDatabase):
    """
    SR-17: the count runs in its own read-only transaction on a second connection, which only sees
    committed rows. So, like SR-03's and SR-14's concurrency tests, these replace the db_session and
    client fixtures with committing ones, and empty the test database afterwards (TRUNCATE, which
    the append-only triggers do not stop).
    SR-18: fixtures and helpers only, no tests, so the release tests can build on the same setup.
    """

    @pytest.fixture
    def keys(self, checkpoint_keys):
        private_path, public_path = checkpoint_keys
        return load_private_key(private_path), load_checkpoint_public_key(public_path)

    @pytest.fixture
    def cast(self, client: TestClient, make_voter, sign_in):
        """SR-17: one real ballot through the API, numbered in the order given (by ballot position)."""

        def vote(division: str, order: list[int]) -> list[int]:
            sign_in(make_voter(division=division))
            paper = client.get("/api/ballot").json()
            ranking = [paper["candidates"][i]["id"] for i in order]
            response = client.post("/api/ballot/submit", json={"ballot_token": paper["ballot_token"], "ranked_candidate_ids": ranking})
            assert response.status_code == 200
            return ranking

        return vote

    @pytest.fixture
    def sealed(self, db_session: Session, election, cast, keys, clock):
        """
        SR-17: five Northgate ballots, polls closed (clock moved past ends_at), and a final seal.
        First preferences: Ortega 2, Whitfield 2, Tran 1, so Tran is excluded and Whitfield elected.
        """
        rankings = [cast("Northgate", order) for order in ([0, 1, 2], [0, 1, 2], [1, 2, 0], [1, 2, 0], [2, 1, 0])]
        clock.advance(days=2)
        election_id = election.election.id
        assert seal_batch(db_session, election_id, True, *keys, checkpoint_file(election_id)).reasons == []
        return {"election_id": election_id, "rankings": rankings}

    def count(self, engine: Engine, keys, election_id: uuid.UUID) -> dict:
        return run_count(engine, election_id, keys[1], checkpoint_file(election_id))

    def refusal(self, engine: Engine, keys, election_id: uuid.UUID) -> CountRefused:
        with pytest.raises(CountRefused) as refused:
            self.count(engine, keys, election_id)
        return refused.value

    def chain(self, db: Session, election_id: uuid.UUID) -> list[BallotChainEntry]:
        db.expire_all()
        return list(db.scalars(select(BallotChainEntry).where(BallotChainEntry.election_id == election_id).order_by(BallotChainEntry.position)))


class TestHouseCount(CountedElection):
    """SR-17: the count over a real, committed election, and every way it is refused."""

    # -- a clean count --

    def test_a_clean_election_counts_and_the_result_holds_totals_only(
        self, engine: Engine, db_session: Session, election, sealed, keys, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        """SR-17: rounds, exclusion and winner as worked out by hand; the result file holds totals and names only."""
        monkeypatch.setattr(count_house, "engine", engine)
        out = tmp_path / "result.json"

        assert count_house.main(["--election", str(sealed["election_id"]), "--out", str(out)]) == 0

        printed = capsys.readouterr().out
        assert "Round 1: Hana Ortega 2, Daniel Whitfield 2, Mei-Lin Tran 1; excluded Mei-Lin Tran" in printed
        assert "Round 2: Hana Ortega 2, Daniel Whitfield 3" in printed and "Elected: Daniel Whitfield (Rural Alliance)" in printed
        result = json.loads(out.read_text(encoding="utf-8"))
        northgate, southvale = result["divisions"]
        assert (northgate["status"], northgate["formal_total"], northgate["elected"]["name"]) == ("elected", 5, "Daniel Whitfield")
        assert [[t["votes"] for t in r["totals"]] for r in northgate["rounds"]] == [[2, 2, 1], [2, 3]]
        assert (southvale["status"], southvale["elected"], southvale["rounds"]) == ("no_ballots", None, [])
        assert result["ballots_counted"] == 5 and set(result) == {"election_id", "election", "ballots_counted", "final_checkpoint", "divisions"}
        file_text = out.read_text(encoding="utf-8")
        for entry in self.chain(db_session, sealed["election_id"]):
            assert str(entry.ballot_id) not in file_text
        assert "ranked_candidate_ids" not in file_text and "ballot_token" not in file_text
        assert all(set(d) == {"division_id", "division", "status", "formal_total", "rounds", "elected"} for d in result["divisions"])

    # -- each check stops the count --

    def test_refused_while_polls_are_open(self, engine: Engine, db_session: Session, election, cast, keys) -> None:
        """SR-17 check a: sealed, but before polls close: polls_open, and nothing is counted."""
        cast("Northgate", [0, 1, 2])
        election_id = election.election.id
        seal_batch(db_session, election_id, True, *keys, checkpoint_file(election_id))

        assert self.refusal(engine, keys, election_id).code == "polls_open"

    def test_refused_without_a_final_checkpoint(
        self, engine: Engine, db_session: Session, election, cast, keys, clock, monkeypatch
    ) -> None:
        """SR-17 check c: only a non-final seal exists, so more ballots could still belong: no_final_checkpoint."""
        monkeypatch.setattr(settings, "min_seal_batch", 1)
        cast("Northgate", [0, 1, 2])
        clock.advance(days=2)
        election_id = election.election.id
        assert seal_batch(db_session, election_id, False, *keys, checkpoint_file(election_id)).final is False

        assert self.refusal(engine, keys, election_id).code == "no_final_checkpoint"

    def test_refused_when_the_definition_is_altered(self, engine: Engine, db_session: Session, sealed, keys) -> None:
        """SR-17 check b: a candidate's name changed in the stored definition: definition_invalid."""
        db_session.execute(text("UPDATE ballot_definitions SET payload = replace(payload, 'Whitfield', 'Whitley') WHERE is_active"))
        db_session.commit()

        assert self.refusal(engine, keys, sealed["election_id"]).code == "definition_invalid"

    @pytest.mark.parametrize("tampering", ["altered ciphertext", "injected chain entry", "removed ballot", "unsealed ballot"])
    def test_refused_when_the_chain_does_not_verify(
        self, engine: Engine, db_session: Session, sealed, keys, tampering: str
    ) -> None:
        """SR-17 check d: an altered, injected, removed or unsealed ballot: chain_invalid, with the SR-13 codes."""
        election_id = sealed["election_id"]
        first = self.chain(db_session, election_id)[0]
        kept = db_session.scalar(text("SELECT encrypted_payload FROM ballots WHERE id = :id"), {"id": first.ballot_id})
        stray = uuid.uuid4()
        stray_blob = encrypt_ballot(ballot_payload(1, [1, 2, 3]), stray, election_id)
        insert_stray = text("INSERT INTO ballots (id, election_id, encrypted_payload) VALUES (:i, :e, :p)")
        with triggers_off(db_session, "ballots", "ballot_chain"):
            if tampering == "altered ciphertext":
                db_session.execute(text("UPDATE ballots SET encrypted_payload = encrypted_payload || '\\x00'::bytea WHERE id = :id"), {"id": first.ballot_id})
            elif tampering == "injected chain entry":
                db_session.execute(insert_stray, {"i": stray, "e": election_id, "p": stray_blob})
                db_session.execute(
                    text("INSERT INTO ballot_chain (election_id, position, batch_no, ballot_id, prev_hash, entry_hash) VALUES (:e, 6, 1, :i, :prev, :h)"),
                    {"e": election_id, "i": stray, "prev": self.chain(db_session, election_id)[-1].entry_hash, "h": "0" * 64},
                )
            elif tampering == "removed ballot":
                # The foreign key also guards a chained ballot, so the "attacker" drops it too
                db_session.execute(text("ALTER TABLE ballot_chain DROP CONSTRAINT fk_ballot_chain_ballot_id_ballots"))
                db_session.execute(text("DELETE FROM ballots WHERE id = :id"), {"id": first.ballot_id})
            else:
                db_session.execute(insert_stray, {"i": stray, "e": election_id, "p": stray_blob})

        try:
            refused = self.refusal(engine, keys, election_id)
        finally:
            if tampering == "removed ballot":
                # These rows are committed, so the ballot and the foreign key are put back by hand
                db_session.execute(insert_stray, {"i": first.ballot_id, "e": election_id, "p": kept})
                db_session.execute(
                    text(
                        "ALTER TABLE ballot_chain ADD CONSTRAINT fk_ballot_chain_ballot_id_ballots "
                        "FOREIGN KEY (ballot_id) REFERENCES ballots (id)"
                    )
                )
                db_session.commit()

        expected = {
            "altered ciphertext": "bad_entry_hash",
            "injected chain entry": "tail_mismatch",
            "removed ballot": "missing_ballot",
            "unsealed ballot": "unsealed_after_final",
        }[tampering]
        assert refused.code == "chain_invalid" and expected in refused.details

    def rewrite_ballot(self, db: Session, election_id: uuid.UUID, keys, blob: bytes) -> None:
        """
        SR-17: replaces the first sealed ballot and re-makes every later link and the checkpoint with
        the checkpoint key, as an attacker holding that key could. The chain then verifies, so only
        the later checks (decryption, division, formality) can stop the count.
        """
        entries = self.chain(db, election_id)
        with triggers_off(db, "ballots", "ballot_chain"):
            db.execute(text("UPDATE ballots SET encrypted_payload = :p WHERE id = :id"), {"p": blob, "id": entries[0].ballot_id})
            prev = entries[0].prev_hash
            for entry in entries:
                payload = db.scalar(text("SELECT encrypted_payload FROM ballots WHERE id = :id"), {"id": entry.ballot_id})
                entry_hash = compute_entry_hash(prev, entry.ballot_id, election_id, payload)
                db.execute(
                    text("UPDATE ballot_chain SET prev_hash = :prev, entry_hash = :h WHERE election_id = :e AND position = :p"),
                    {"prev": prev, "h": entry_hash, "e": election_id, "p": entry.position},
                )
                prev = entry_hash
        path = checkpoint_file(election_id)
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        path.unlink()
        for line in lines:
            line.pop("signature")
            append_checkpoint(path, line | {"head_hash": prev}, keys[0])
        assert verify_chain(db, election_id, keys[1], path) == []

    @pytest.mark.parametrize(
        ("forgery", "code"),
        [
            ("another election's ciphertext", "decrypt_failed"),
            ("a division not on the definition", "wrong_division"),
            ("an incomplete ranking", "informal_or_invalid"),
            ("a candidate twice", "informal_or_invalid"),
        ],
    )
    def test_refused_for_a_ballot_that_passes_the_chain_but_not_its_own_checks(
        self, engine: Engine, db_session: Session, election, sealed, keys, forgery: str, code: str
    ) -> None:
        """SR-17 checks g, h, i: a forged ballot behind a re-signed chain is still refused, and not skipped."""
        election_id = sealed["election_id"]
        ballot_id = self.chain(db_session, election_id)[0].ballot_id
        northgate = election.divisions["Northgate"].id
        full = sealed["rankings"][0]
        blob = {
            "another election's ciphertext": encrypt_ballot(ballot_payload(northgate, full), uuid.uuid4(), uuid.uuid4()),
            "a division not on the definition": encrypt_ballot(ballot_payload(999_999, full), ballot_id, election_id),
            "an incomplete ranking": encrypt_ballot(ballot_payload(northgate, full[:2]), ballot_id, election_id),
            "a candidate twice": encrypt_ballot(ballot_payload(northgate, [full[0], full[0], full[1]]), ballot_id, election_id),
        }[forgery]
        self.rewrite_ballot(db_session, election_id, keys, blob)

        refused = self.refusal(engine, keys, election_id)

        assert (refused.code, refused.checked) == (code, 0)

    def test_refused_when_the_voted_total_does_not_match(self, engine: Engine, db_session: Session, sealed, keys, monkeypatch) -> None:
        """SR-17 check f: one fewer elector marked voted than ballots sealed: total_mismatch (totals only).
        VULN-02: check d now compares the totals first (ballot_count_mismatch); with d out of the way,
        as if it had a bug, check f still refuses with total_mismatch."""
        db_session.execute(
            text("UPDATE voter_participation SET state = 'issued' WHERE roll_id = (SELECT roll_id FROM voter_participation LIMIT 1)")
        )
        db_session.commit()

        refused = self.refusal(engine, keys, sealed["election_id"])
        assert (refused.code, refused.details) == ("chain_invalid", ["ballot_count_mismatch"])
        monkeypatch.setattr(house_count, "verify_chain", lambda *args: [])
        assert self.refusal(engine, keys, sealed["election_id"]).code == "total_mismatch"

    # -- how the ballots are read --

    def test_the_loader_reads_only_ballots_in_the_chain(self, engine: Engine, db_session: Session, sealed, keys) -> None:
        """SR-17 check e: an unsealed ballot is never returned, nor a position past the checkpoint's count."""
        election_id = sealed["election_id"]
        stray = uuid.uuid4()
        db_session.execute(
            text("INSERT INTO ballots (id, election_id, encrypted_payload) VALUES (:i, :e, :p)"),
            {"i": stray, "e": election_id, "p": encrypt_ballot(ballot_payload(1, [1]), stray, election_id)},
        )
        db_session.commit()
        chained = [(e.position, e.ballot_id) for e in self.chain(db_session, election_id)]

        with house_count.read_only_snapshot(engine) as session:
            # Through the module, so this checks the function the loader really calls
            everything = house_count.read_chained_ballots(session, election_id, 5)
            first_three = house_count.read_chained_ballots(session, election_id, 3)

        assert [(r.position, r.ballot_id) for r in everything] == chained
        assert [(r.position, r.ballot_id) for r in first_three] == chained[:3]
        assert stray not in {r.ballot_id for r in everything}

    def test_an_unsealed_ballot_is_not_read_even_if_the_chain_check_missed_it(
        self, engine: Engine, db_session: Session, sealed, keys, monkeypatch
    ) -> None:
        """SR-17 check e, in depth: with check d disabled as if it had a bug, the unsealed ballot is still never counted."""
        election_id = sealed["election_id"]
        stray = uuid.uuid4()
        db_session.execute(
            text("INSERT INTO ballots (id, election_id, encrypted_payload) VALUES (:i, :e, :p)"),
            {"i": stray, "e": election_id, "p": encrypt_ballot(ballot_payload(1, [1]), stray, election_id)},
        )
        db_session.commit()
        monkeypatch.setattr(house_count, "verify_chain", lambda *args: [])

        result = self.count(engine, keys, election_id)

        assert result["ballots_counted"] == 5 and result["divisions"][0]["formal_total"] == 5

    def test_check_ballot_on_crafted_payloads(self, election, sealed, db_session: Session) -> None:
        """SR-17 checks g, h, i directly: the right ballot passes; a mismatched blob, division or ranking stops."""
        election_id, ballot_id = sealed["election_id"], uuid.uuid4()
        with house_count.read_only_snapshot(db_session.get_bind()) as session:
            definition = house_count.active_definition(session, election_id)
            papers = house_count.division_papers(definition.payload)
        northgate, full = election.divisions["Northgate"].id, sealed["rankings"][0]

        assert check_ballot(encrypt_ballot(ballot_payload(northgate, full), ballot_id, election_id), ballot_id, election_id, papers) == (northgate, full)
        for blob, code in (
            (encrypt_ballot(ballot_payload(northgate, full), uuid.uuid4(), election_id), "decrypt_failed"),
            (encrypt_ballot(ballot_payload(northgate + 10_000, full), ballot_id, election_id), "wrong_division"),
            (encrypt_ballot(ballot_payload(northgate, list(reversed(full))[:1]), ballot_id, election_id), "informal_or_invalid"),
        ):
            with pytest.raises(CountRefused) as refused:
                check_ballot(blob, ballot_id, election_id, papers)
            assert refused.value.code == code and str(ballot_id) not in str(refused.value)

    def test_the_count_transaction_is_read_only(self, engine: Engine, sealed, keys, monkeypatch) -> None:
        """SR-17: inside the count's transaction an INSERT fails; it is REPEATABLE READ, one snapshot."""
        seen = {}
        real_loader = house_count.load_validated_ballots

        def loader(session, *args):
            seen["isolation"] = session.scalar(text("SHOW transaction_isolation"))
            savepoint = session.begin_nested()
            try:
                session.execute(text("INSERT INTO divisions (name, state) VALUES ('Nowhere', 'Victoria')"))
            except DBAPIError as problem:
                seen["error"] = str(problem.orig).splitlines()[0]
            savepoint.rollback()
            return real_loader(session, *args)

        monkeypatch.setattr(house_count, "load_validated_ballots", loader)

        assert self.count(engine, keys, sealed["election_id"])["ballots_counted"] == 5
        assert seen == {"isolation": "repeatable read", "error": "cannot execute INSERT in a read-only transaction"}

    # -- nothing leaks, nothing else breaks --

    def test_no_ballot_content_leaks_and_count_events_hold_only_allowed_fields(
        self, engine: Engine, db_session: Session, election, sealed, keys, tmp_path: Path, monkeypatch, caplog, capsys
    ) -> None:
        """SR-17: no division-plus-ranking in logs, the audit log or the result; count events are SR-16 shaped."""
        caplog.set_level(logging.DEBUG)
        monkeypatch.setattr(count_house, "engine", engine)
        out = tmp_path / "result.json"
        before = db_session.scalar(select(AuditLogEntry.id).order_by(AuditLogEntry.id.desc()).limit(1))
        count_house.main(["--election", str(sealed["election_id"]), "--out", str(out)])
        db_session.execute(text("UPDATE voter_participation SET state = 'issued' WHERE roll_id = (SELECT roll_id FROM voter_participation LIMIT 1)"))
        db_session.commit()
        assert count_house.main(["--election", str(sealed["election_id"]), "--out", str(tmp_path / "refused.json")]) == 1

        northgate = election.divisions["Northgate"].id
        decrypted = [json.dumps(ballot_payload(northgate, ranking), sort_keys=True) for ranking in sealed["rankings"]]
        decrypted += [json.dumps(ranking) for ranking in sealed["rankings"]]
        audit_rows = " ".join(db_session.scalars(text("SELECT row_to_json(a)::text FROM audit_log a")))
        places = {"logs": caplog.text, "output": capsys.readouterr().out, "audit log": audit_rows, "result": out.read_text(encoding="utf-8")}
        assert {place: [d for d in decrypted if d in content] for place, content in places.items()} == dict.fromkeys(places, [])
        assert not (tmp_path / "refused.json").exists()

        db_session.expire_all()
        events = list(db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.id > before, AuditLogEntry.event_type.like("COUNT_%")).order_by(AuditLogEntry.id)))
        assert [(e.event_type, e.outcome, e.reason, e.count) for e in events] == [
            ("COUNT_STARTED", "success", None, None),
            ("COUNT_COMPLETED", "success", None, 5),
            ("COUNT_STARTED", "success", None, None),
            # VULN-02: the changed total is now caught by check d, the chain check, before check f
            ("COUNT_REFUSED", "failure", "chain_invalid", 0),
        ]
        assert all(
            # SR-18: written in the current audit format; a count event has no release version
            (e.category, e.actor, e.role, e.details, e.batch_no, e.version, e.format_version)
            == ("ballot_box", "script", "script", None, None, None, AUDIT_FORMAT_CURRENT)
            and e.request_id is not None
            for e in events
        )

    def test_after_a_count_the_earlier_audits_still_pass(
        self, engine: Engine, db_session: Session, sealed, keys, tmp_path: Path
    ) -> None:
        """SR-17: after counting, the SR-11 and SR-12 audits, verify_chain (SR-13) and verify_audit (SR-16) all pass."""
        election_id = sealed["election_id"]
        self.count(engine, keys, election_id)
        db_session.expire_all()

        assert {c.status for c in audit_ballots.run_audit(db_session, tmp_path)} <= {"PASS", "SKIPPED"}
        assert {c.status for c in audit_separation.run_audit(db_session, [], tmp_path, tmp_path / "logs")} <= {"PASS", "SKIPPED"}
        assert verify_chain(db_session, election_id, keys[1], checkpoint_file(election_id)) == []
        audit_path = tmp_path / "audit.jsonl"
        audit_checkpoint.sign_audit_checkpoint(db_session, keys[0], keys[1], audit_path)
        assert all(problem is None for problem in verify_audit.verify_audit(db_session, keys[1], audit_path).values())
        assert audit_hash_at(db_session, 1) is not None
        assert db_session.scalar(select(VoterParticipation.state).limit(1)) == ParticipationState.VOTED
