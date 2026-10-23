"""
SR-13: accepted ballots are sealed into a SHA-256 hash chain with signed checkpoints, and the
integrity tests detect insertion, deletion, modification and reordering of recorded ballots.
Tampering is done the only way the database still allows it: by switching off the append-only
trigger inside the test (as a database owner could), then switching it back on.
"""

import base64
import json
import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.ballot_chain import (
    checkpoint_file,
    checkpoint_message,
    compute_entry_hash,
    load_checkpoint_public_key,
    start_hash,
    verify_chain,
)
from app.ballot_crypto import ballot_payload, encrypt_ballot
from app.ballot_definitions import canonical
from app.config import settings
from app.main import app
from app.models import AuditLogEntry, BallotChainEntry
from app.security import audit
from scripts import audit_ballots, audit_separation, seal_ballots
from scripts import verify_chain as verify_script
from scripts.gen_checkpoint_key import generate_checkpoint_keys
from scripts.seal_ballots import SealRefused, SealResult, load_private_key, seal_batch

Keys = tuple[Ed25519PrivateKey, Ed25519PublicKey]


@pytest.fixture
def keys(checkpoint_keys: tuple[Path, Path]) -> Keys:
    """SR-13: the test run's checkpoint key pair (conftest), loaded."""
    private_path, public_path = checkpoint_keys
    return load_private_key(private_path), load_checkpoint_public_key(public_path)


@pytest.fixture
def election_id(election) -> uuid.UUID:
    return election.election.id


def add_ballots(db: Session, election_id: uuid.UUID, count: int = 0, ids: list[uuid.UUID] | None = None) -> list[uuid.UUID]:
    """SR-13: stored ballots as SR-11 leaves them (real ciphertext), inserted in the order given."""
    ids = ids or [uuid.uuid4() for _ in range(count)]
    for ballot_id in ids:
        db.execute(
            text("INSERT INTO ballots (id, election_id, encrypted_payload) VALUES (:i, :e, :p)"),
            {"i": ballot_id, "e": election_id, "p": encrypt_ballot(ballot_payload(1, [1, 2, 3]), ballot_id, election_id)},
        )
    db.commit()
    return ids


def seal(db: Session, election_id: uuid.UUID, keys: Keys, final: bool = False) -> SealResult:
    return seal_batch(db, election_id, final, *keys, checkpoint_file(election_id))


def verify(db: Session, election_id: uuid.UUID, keys: Keys) -> list[str]:
    return verify_chain(db, election_id, keys[1], checkpoint_file(election_id))


def three_batches(db: Session, election_id: uuid.UUID, keys: Keys) -> None:
    """SR-13: 30 ballots sealed as batches of 10, the last one final."""
    for batch in range(3):
        add_ballots(db, election_id, 10)
        assert seal(db, election_id, keys, final=batch == 2).reasons == []


def chain(db: Session, election_id: uuid.UUID) -> list[BallotChainEntry]:
    db.expire_all()
    return list(db.scalars(select(BallotChainEntry).where(BallotChainEntry.election_id == election_id).order_by(BallotChainEntry.position)))


@contextmanager
def triggers_off(db: Session, *tables: str) -> Iterator[None]:
    """SR-13: tampering as only a database owner could. Back on afterwards (and the test's transaction is rolled back)."""
    for table in tables:
        db.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER {table}_append_only"))
    try:
        yield
    finally:
        for table in tables:
            db.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER {table}_append_only"))


# ---------------------------------------------------------------
# A clean chain
# ---------------------------------------------------------------


def test_clean_chain_over_three_batches_verifies(db_session: Session, election_id: uuid.UUID, keys: Keys) -> None:
    """SR-13 test 1: three sealed batches verify, link by link, with one signed checkpoint each."""
    three_batches(db_session, election_id, keys)

    entries = chain(db_session, election_id)
    assert verify(db_session, election_id, keys) == []
    assert [e.position for e in entries] == list(range(1, 31))
    assert [e.batch_no for e in entries] == [1] * 10 + [2] * 10 + [3] * 10
    assert [e.prev_hash for e in entries] == [start_hash(election_id)] + [e.entry_hash for e in entries[:-1]]
    lines = [json.loads(line) for line in checkpoint_file(election_id).read_text().splitlines()]
    assert [(c["batch_no"], c["entry_count"], c["final"]) for c in lines] == [(1, 10, False), (2, 20, False), (3, 30, True)]
    assert lines[-1]["head_hash"] == entries[-1].entry_hash
    sealed = db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.event_type == "BALLOT_BATCH_SEALED")).all()
    assert [(e.actor, e.details) for e in sealed] == [("script", {"batch": n, "count": 10}) for n in (1, 2, 3)]


def test_chain_order_follows_ballot_id_not_arrival(db_session: Session, election_id: uuid.UUID, keys: Keys) -> None:
    """SR-13 test 2: ballots that arrived in descending id order are chained in ascending id order."""
    arrived = sorted((uuid.uuid4() for _ in range(12)), reverse=True)
    add_ballots(db_session, election_id, ids=arrived)

    seal(db_session, election_id, keys)

    assert [e.ballot_id for e in chain(db_session, election_id)] == sorted(arrived)


def test_verification_never_needs_the_ballot_key(db_session: Session, election_id: uuid.UUID, keys: Keys, tmp_path: Path, monkeypatch) -> None:
    """SR-13 test 3: the chain covers ciphertext, so verifying works without the SR-11 key: nothing is decrypted."""
    three_batches(db_session, election_id, keys)
    monkeypatch.setattr(settings, "ballot_key_file", tmp_path / "no-such.key")

    assert verify(db_session, election_id, keys) == []


# ---------------------------------------------------------------
# Insertion, deletion, modification, reordering
# ---------------------------------------------------------------


def test_insertion_of_a_forged_chain_entry_is_detected(db_session: Session, election_id: uuid.UUID, keys: Keys) -> None:
    """SR-13 test 4: a chain entry appended for a new ballot, even with correct hashes, no longer matches the signed tail."""
    add_ballots(db_session, election_id, 10)
    seal(db_session, election_id, keys)
    tail = chain(db_session, election_id)[-1]
    (forged,) = add_ballots(db_session, election_id, 1)
    payload = db_session.scalar(text("SELECT encrypted_payload FROM ballots WHERE id = :i"), {"i": forged})
    db_session.add(
        BallotChainEntry(
            election_id=election_id,
            position=11,
            batch_no=tail.batch_no,
            ballot_id=forged,
            prev_hash=tail.entry_hash,
            entry_hash=compute_entry_hash(tail.entry_hash, forged, election_id, payload),
        )
    )
    db_session.commit()

    assert "tail_mismatch" in verify(db_session, election_id, keys)


def test_ballot_added_after_the_final_seal_is_detected(db_session: Session, election_id: uuid.UUID, keys: Keys) -> None:
    """SR-13 test 5: once a final checkpoint exists, an unsealed ballot of that election fails verification."""
    three_batches(db_session, election_id, keys)

    add_ballots(db_session, election_id, 1)

    assert verify(db_session, election_id, keys) == ["unsealed_after_final"]


@pytest.mark.parametrize(
    ("tampering", "expected"),
    [
        ("remove a chain entry", {"gap_or_reorder", "broken_link"}),
        ("remove a ballot", {"missing_ballot"}),
        ("truncate the tail", {"tail_mismatch"}),
    ],
)
def test_deletion_is_detected(db_session: Session, election_id: uuid.UUID, keys: Keys, tampering: str, expected: set[str]) -> None:
    """SR-13 test 6: a removed chain entry, a removed ballot, or the last batch cut off the chain."""
    three_batches(db_session, election_id, keys)
    entries = chain(db_session, election_id)
    with triggers_off(db_session, "ballots", "ballot_chain"):
        if tampering == "remove a chain entry":
            db_session.execute(text("DELETE FROM ballot_chain WHERE election_id = :e AND position = 5"), {"e": election_id})
        elif tampering == "remove a ballot":
            # The foreign key also guards a chained ballot, so the "attacker" drops it too (undone with the test)
            db_session.execute(text("ALTER TABLE ballot_chain DROP CONSTRAINT fk_ballot_chain_ballot_id_ballots"))
            db_session.execute(text("DELETE FROM ballots WHERE id = :i"), {"i": entries[4].ballot_id})
        else:
            db_session.execute(text("DELETE FROM ballot_chain WHERE election_id = :e AND batch_no = 3"), {"e": election_id})

    assert expected <= set(verify(db_session, election_id, keys))


@pytest.mark.parametrize(
    ("tampering", "expected"),
    [("change a ballot's ciphertext", {"bad_entry_hash"}), ("change an entry hash", {"bad_entry_hash", "broken_link"})],
)
def test_modification_is_detected(db_session: Session, election_id: uuid.UUID, keys: Keys, tampering: str, expected: set[str]) -> None:
    """SR-13 test 7: a different (even validly encrypted) ballot in a sealed row, or an edited hash."""
    three_batches(db_session, election_id, keys)
    target = chain(db_session, election_id)[6]
    with triggers_off(db_session, "ballots", "ballot_chain"):
        if tampering == "change a ballot's ciphertext":
            # A genuine SR-11 ciphertext for this very row, so decryption alone would never notice
            swapped = encrypt_ballot(ballot_payload(1, [3, 2, 1]), target.ballot_id, election_id)
            db_session.execute(text("UPDATE ballots SET encrypted_payload = :p WHERE id = :i"), {"p": swapped, "i": target.ballot_id})
        else:
            db_session.execute(text("UPDATE ballot_chain SET entry_hash = :h WHERE ballot_id = :i"), {"h": "f" * 64, "i": target.ballot_id})

    assert expected <= set(verify(db_session, election_id, keys))


@pytest.mark.parametrize(("first", "second", "expected"), [(3, 8, {"broken_link"}), (5, 15, {"broken_link", "gap_or_reorder"})])
def test_reordering_is_detected(
    db_session: Session, election_id: uuid.UUID, keys: Keys, first: int, second: int, expected: set[str]
) -> None:
    """SR-13 test 8: two entries swapped, within a batch or across batches."""
    three_batches(db_session, election_id, keys)
    with triggers_off(db_session, "ballot_chain"):
        for old, new in ((first, -1), (second, first), (-1, second)):
            db_session.execute(
                text("UPDATE ballot_chain SET position = :new WHERE election_id = :e AND position = :old"),
                {"new": new, "old": old, "e": election_id},
            )

    assert expected <= set(verify(db_session, election_id, keys))


# ---------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("tampering", "expected"),
    [
        ("forged", "bad_checkpoint_signature"),
        ("edited", "bad_checkpoint_signature"),
        ("reordered", "checkpoint_mismatch"),
        ("line removed", "checkpoint_mismatch"),
        ("last line removed", "tail_mismatch"),
        ("malformed", "malformed_checkpoint"),
        ("file missing", "missing_checkpoint"),
    ],
)
def test_checkpoint_tampering_is_detected(
    db_session: Session, election_id: uuid.UUID, keys: Keys, tampering: str, expected: str
) -> None:
    """SR-13 test 9: a forged, edited, reordered, removed or malformed checkpoint line, or no file at all."""
    three_batches(db_session, election_id, keys)
    path = checkpoint_file(election_id)
    lines = path.read_text().splitlines()
    if tampering == "forged":
        content = {k: v for k, v in json.loads(lines[1]).items() if k != "signature"}
        signature = Ed25519PrivateKey.generate().sign(checkpoint_message(content))
        lines[1] = canonical(content | {"signature": base64.b64encode(signature).decode()})
    elif tampering == "edited":
        record = json.loads(lines[1])
        lines[1] = canonical(record | {"entry_count": 25})
    elif tampering == "reordered":
        lines[0], lines[1] = lines[1], lines[0]
    elif tampering == "line removed":
        del lines[1]
    elif tampering == "last line removed":
        del lines[-1]
    elif tampering == "malformed":
        lines[1] = '{"batch_no": 2, "signature": "not base64!"'
    if tampering == "file missing":
        path.unlink()
    else:
        path.write_text("\n".join(lines) + "\n")

    assert expected in verify(db_session, election_id, keys)


# ---------------------------------------------------------------
# Append-only storage
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE ballots SET encrypted_payload = encrypted_payload WHERE id = :i",
        "DELETE FROM ballots WHERE id = :u",
        "UPDATE ballot_chain SET batch_no = batch_no WHERE ballot_id = :i",
        "DELETE FROM ballot_chain WHERE ballot_id = :i",
    ],
)
def test_triggers_reject_update_and_delete_but_allow_insert(
    db_session: Session, election_id: uuid.UUID, keys: Keys, statement: str
) -> None:
    """SR-13 test 10: UPDATE and DELETE are refused on ballots and ballot_chain (even an unsealed ballot); INSERT works."""
    (sealed,) = add_ballots(db_session, election_id, 1)
    seal(db_session, election_id, keys, final=True)
    (unsealed,) = add_ballots(db_session, election_id, 1)  # INSERT still allowed

    savepoint = db_session.begin_nested()
    with pytest.raises(DBAPIError, match="is not allowed: recorded ballots are append-only"):
        db_session.execute(text(statement), {"i": sealed, "u": unsealed})
    savepoint.rollback()

    assert db_session.scalar(text("SELECT count(*) FROM ballots WHERE election_id = :e"), {"e": election_id}) == 2


# ---------------------------------------------------------------
# The seal and verify scripts
# ---------------------------------------------------------------


def run_seal(db: Session, monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(seal_ballots, "SessionLocal", lambda: nullcontext(db))
    return seal_ballots.main(list(argv))


def test_small_batch_is_refused_unless_final(db_session: Session, election_id: uuid.UUID, keys: Keys, monkeypatch, capsys) -> None:
    """SR-13 test 11: fewer than MIN_SEAL_BATCH ballots are refused, then sealed with --final, and nothing after that."""
    add_ballots(db_session, election_id, 3)

    assert run_seal(db_session, monkeypatch, "--election", str(election_id)) == 1
    refused = capsys.readouterr().out
    assert "REFUSED: only 3 unsealed ballot(s); a batch needs at least MIN_SEAL_BATCH=10" in refused
    assert chain(db_session, election_id) == [] and not checkpoint_file(election_id).exists()

    assert run_seal(db_session, monkeypatch, "--election", str(election_id), "--final") == 0
    sealed = capsys.readouterr().out
    assert f"Head hash: {chain(db_session, election_id)[-1].entry_hash}" in sealed
    assert "Verification: PASS" in sealed and "Final seal: no more ballots may be accepted for this election." in sealed

    add_ballots(db_session, election_id, 10)
    assert run_seal(db_session, monkeypatch, "--election", str(election_id)) == 1
    assert "already had its final seal" in capsys.readouterr().out


def test_sealing_twice_with_no_new_ballots_is_refused(db_session: Session, election_id: uuid.UUID, keys: Keys) -> None:
    """SR-13 test 12: an empty batch is never sealed."""
    add_ballots(db_session, election_id, 10)
    seal(db_session, election_id, keys)

    with pytest.raises(SealRefused, match="no unsealed ballots"):
        seal(db_session, election_id, keys)
    assert len(checkpoint_file(election_id).read_text().splitlines()) == 1


@pytest.mark.parametrize("blocked", ["the folder", "the file"])
def test_seal_refuses_when_the_checkpoint_cannot_be_written(
    db_session: Session, election_id: uuid.UUID, keys: Keys, tmp_path: Path, monkeypatch, blocked: str
) -> None:
    """SR-13 test 12b: an unwritable checkpoint folder or file refuses the seal before anything is committed, so no batch lacks its checkpoint."""
    add_ballots(db_session, election_id, 10)
    if blocked == "the folder":
        (tmp_path / "not-a-folder").write_text("a file where the checkpoint folder should be")
        monkeypatch.setattr(settings, "checkpoint_dir", tmp_path / "not-a-folder" / "checkpoints")
    else:
        # the folder is fine, but the checkpoint file itself cannot be opened (here: a folder has its name)
        monkeypatch.setattr(settings, "checkpoint_dir", tmp_path)
        (tmp_path / f"{election_id}.jsonl").mkdir()

    with pytest.raises(SealRefused, match="checkpoint file cannot be written"):
        seal(db_session, election_id, keys)

    assert chain(db_session, election_id) == []
    monkeypatch.setattr(settings, "checkpoint_dir", tmp_path / "working")
    assert seal(db_session, election_id, keys).reasons == []


def test_seal_refuses_to_extend_a_chain_that_fails(db_session: Session, election_id: uuid.UUID, keys: Keys) -> None:
    """SR-13 test 13: no new checkpoint is ever signed over a tampered chain, and the failure is audited by reason only."""
    add_ballots(db_session, election_id, 10)
    seal(db_session, election_id, keys)
    with triggers_off(db_session, "ballot_chain"):
        db_session.execute(text("UPDATE ballot_chain SET entry_hash = :h WHERE position = 4 AND election_id = :e"), {"h": "0" * 64, "e": election_id})
    add_ballots(db_session, election_id, 10)

    with pytest.raises(SealRefused, match="does not verify"):
        seal(db_session, election_id, keys)

    failure = db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.event_type == "BALLOT_CHAIN_VERIFY_FAILED")).one()
    assert (failure.actor, failure.details) == ("script", {"reason": "bad_entry_hash,broken_link"})
    assert len(chain(db_session, election_id)) == 10


def test_verify_script_passes_then_fails_after_tampering(db_session: Session, election_id: uuid.UUID, keys: Keys, monkeypatch, capsys) -> None:
    """SR-13 test 14: one line per check group, the head hash to record, and exit code 1 on tampering."""
    three_batches(db_session, election_id, keys)
    monkeypatch.setattr(verify_script, "SessionLocal", lambda: nullcontext(db_session))

    assert verify_script.main(["--election", str(election_id)]) == 0
    clean = capsys.readouterr().out
    assert clean.count("PASS     ") == 6 and clean.rstrip().endswith("SR-13 chain verification: PASS")
    assert f"Entries: 30. Head hash: {chain(db_session, election_id)[-1].entry_hash}" in clean

    with triggers_off(db_session, "ballots"):
        db_session.execute(text("UPDATE ballots SET encrypted_payload = :p WHERE id = :i"), {"p": b"\x01" + os.urandom(40), "i": chain(db_session, election_id)[0].ballot_id})
    assert verify_script.main(["--election", str(election_id)]) == 1
    tampered = capsys.readouterr().out
    assert "FAIL     a. entry hashes and links: bad_entry_hash" in tampered
    assert tampered.rstrip().endswith("SR-13 chain verification: FAIL (1 checks)")


# ---------------------------------------------------------------
# Keys, start-up, and the SR-11 and SR-12 audits
# ---------------------------------------------------------------


def test_checkpoint_key_script_never_overwrites_without_force(tmp_path: Path) -> None:
    """SR-13 test 15: a second run refuses; --force makes a new pair; the private key is owner-only on POSIX."""
    private, public = tmp_path / "keys" / "checkpoint_private.pem", tmp_path / "keys" / "checkpoint_public.pem"
    generate_checkpoint_keys(private, public)
    first = public.read_bytes()

    with pytest.raises(FileExistsError):
        generate_checkpoint_keys(private, public)
    generate_checkpoint_keys(private, public, force=True)

    assert public.read_bytes() != first
    if os.name == "posix":
        assert private.stat().st_mode & 0o777 == 0o600


def test_api_starts_without_checkpoint_keys(client: TestClient, tmp_path: Path, monkeypatch) -> None:
    """SR-13 test 16: the server never needs the checkpoint keys to start (CI and tests have none)."""
    monkeypatch.setattr(settings, "checkpoint_public_key", tmp_path / "missing_public.pem")
    monkeypatch.setattr(settings, "checkpoint_private_key", tmp_path / "missing_private.pem")

    with TestClient(app):
        pass


def test_sr11_and_sr12_audits_still_pass_with_the_chain(
    client: TestClient, db_session: Session, election_id: uuid.UUID, keys: Keys, make_voter, sign_in, tmp_path: Path
) -> None:
    """SR-13 test 17: a real vote, sealed: both earlier audits pass, and a chain hash on the identity side fails SR-12."""
    sign_in(make_voter())
    paper = client.get("/api/ballot").json()
    ranking = [c["id"] for c in paper["candidates"]]
    assert client.post("/api/ballot/submit", json={"ballot_token": paper["ballot_token"], "ranked_candidate_ids": ranking}).status_code == 200
    seal(db_session, election_id, keys, final=True)

    separation = audit_separation.run_audit(db_session, [], tmp_path, tmp_path / "logs")
    storage = audit_ballots.run_audit(db_session, tmp_path)
    assert {c.status for c in separation} <= {"PASS", "SKIPPED"} and {c.status for c in storage} <= {"PASS", "SKIPPED"}

    audit(db_session, "TEST_EVENT", actor="unknown", note=chain(db_session, election_id)[0].entry_hash)
    identifiers = audit_separation.ballot_identifiers(db_session)
    assert audit_separation.check_identity_tables(db_session, identifiers).status == "FAIL"


@pytest.mark.parametrize(("table", "column"), [("ballots", "position integer"), ("ballot_tokens", "batch_no integer")])
def test_order_numbers_are_allowed_only_on_the_chain(db_session: Session, table: str, column: str) -> None:
    """SR-13 test 18: the SR-12 exception is narrow: position and batch_no pass on ballot_chain, and fail anywhere else."""
    assert audit_separation.check_ballot_columns(db_session).status == "PASS"

    db_session.execute(text(f"ALTER TABLE {table} ADD COLUMN {column}"))
    try:
        check = audit_separation.check_ballot_columns(db_session)
    finally:
        db_session.execute(text(f"ALTER TABLE {table} DROP COLUMN {column.split()[0]}"))

    assert (check.status, check.reason) == ("FAIL", f"{table}.{column.split()[0]} (order number)")
