"""
SR-12: elector identity and ballots stay apart. Every table has one side, the schema has no link
between the sides, no ballot-side row holds anything about an elector or a time of day, nothing on
the identity side or in a log holds a ballot identifier, and the separation audit proves it.
"""

import base64
import json
import logging
import re
import uuid
from contextlib import nullcontext
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, inspect, select, text
from sqlalchemy.orm import Session

from app.ballot_crypto import ballot_payload, encrypt_ballot
from app.config import settings
from app.db import Base
from app.models import Account, AuditLogEntry
from app.security import SESSION_COOKIE, audit, hash_token
from app.stores import BALLOT_TABLES, IDENTITY_TABLES, ballot_rows
from scripts import audit_separation
from scripts.audit_separation import (
    ballot_identifiers,
    check_ballot_columns,
    check_files,
    check_foreign_keys,
    check_identity_tables,
    check_logs,
    has_identity_marker,
    identifiers_in,
    identity_markers,
    run_audit,
)
from scripts.export_ballots import EXPORT_FIELDS, export_ballots

TIME_OF_DAY = re.compile(r"\d{2}:\d{2}(:\d{2})?")


def cast(client: TestClient, make_voter, sign_in) -> dict:
    """SR-12: one real vote through the API, and what the voter saw of it."""
    voter = make_voter()
    sign_in(voter)
    session_cookie = client.cookies.get(SESSION_COOKIE)
    paper = client.get("/api/ballot").json()
    ranking = [c["id"] for c in reversed(paper["candidates"])]
    response = client.post("/api/ballot/submit", json={"ballot_token": paper["ballot_token"], "ranked_candidate_ids": ranking})
    assert response.status_code == 200
    return {"voter": voter, "token": paper["ballot_token"], "ranking": ranking, "receipt": response.json()["receipt_id"], "cookie": session_cookie}


def ballot_side_text(db_session: Session) -> str:
    return " ".join(
        row for table in sorted(BALLOT_TABLES) for row in db_session.scalars(text(f'SELECT row_to_json(t)::text FROM "{table}" AS t'))
    )


def run_main(db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *argv: str) -> int:
    """SR-12: the script's own main(), on the test database, with logs looked for in tmp_path."""
    monkeypatch.setattr(audit_separation, "SessionLocal", lambda: nullcontext(db_session))
    monkeypatch.setattr(audit_separation, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(settings, "log_dir", tmp_path / "logs")
    return audit_separation.main(list(argv))


# ---------------------------------------------------------------
# The two sides and the schema
# ---------------------------------------------------------------


def test_every_model_table_belongs_to_exactly_one_side() -> None:
    """SR-12 test 1: a new table cannot be added without choosing a side in app/stores.py."""
    model_tables = {table.name for table in Base.metadata.sorted_tables}

    assert not IDENTITY_TABLES & BALLOT_TABLES
    assert IDENTITY_TABLES | BALLOT_TABLES == model_tables


def test_schema_keeps_the_sides_apart(engine: Engine, db_session: Session) -> None:
    """SR-12 test 2: no foreign key between the sides; ballot-side columns name no identity, hold no time, are not serial."""
    schema = inspect(engine)
    for table in Base.metadata.sorted_tables:
        for key in schema.get_foreign_keys(table.name):
            sides = {table.name in BALLOT_TABLES, key["referred_table"] in BALLOT_TABLES}
            assert len(sides) == 1, f"{table.name} -> {key['referred_table']}"
    for table in BALLOT_TABLES:
        for column in schema.get_columns(table):
            name, sql_type = column["name"].lower(), column["type"].compile(dialect=engine.dialect).upper()
            assert not any(word in name for word in ("elector", "roll", "user", "session", "agent")), name
            assert "ip" not in name.split("_"), name
            assert "TIME" not in sql_type, f"{table}.{name} is {sql_type}"
            assert not column.get("autoincrement") is True and "nextval" not in str(column.get("default") or ""), name

    assert check_foreign_keys(db_session).status == "PASS"
    assert check_ballot_columns(db_session).status == "PASS"


# ---------------------------------------------------------------
# After a real vote
# ---------------------------------------------------------------


def test_ballot_side_rows_hold_nothing_about_the_elector_or_the_time(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-12 test 3: the raw ballot and token rows hold no elector or roll id, session, IP, user agent or time of day."""
    vote = cast(client, make_voter, sign_in)
    roll_id = db_session.get_one(Account, vote["voter"].account_id).roll_id

    rows = ballot_side_text(db_session)

    assert vote["receipt"] in rows  # the rows were really read
    for value in (
        str(vote["voter"].account_id),
        str(roll_id),
        vote["voter"].username,
        vote["cookie"],
        hash_token(vote["cookie"]).hex(),
        "testclient",  # TestClient's client address and user agent
    ):
        assert value not in rows
    assert not TIME_OF_DAY.search(rows)


def test_no_ballot_identifier_on_the_identity_side(client: TestClient, db_session: Session, make_voter, sign_in) -> None:
    """SR-12 test 4: no ballot id, token id, token hash or receipt in any identity-side table or the audit log."""
    vote = cast(client, make_voter, sign_in)

    identifiers = ballot_identifiers(db_session)

    assert vote["receipt"] in identifiers and hash_token(vote["token"]).hex() in identifiers
    assert len(identifiers) == 4  # ballot id, token id, token hash, receipt
    assert check_identity_tables(db_session, identifiers).status == "PASS"


def test_logs_during_issue_and_submit_name_no_ballot(
    client: TestClient, db_session: Session, make_voter, sign_in, caplog: pytest.LogCaptureFixture
) -> None:
    """SR-12 test 5: nothing logged while issuing and accepting holds a ballot id, token, token hash, receipt or ranking."""
    caplog.set_level(logging.DEBUG)

    vote = cast(client, make_voter, sign_in)

    identifiers = ballot_identifiers(db_session)
    assert not identifiers_in(caplog.text) & identifiers
    for secret in (vote["token"], vote["receipt"], json.dumps(vote["ranking"]), json.dumps(vote["ranking"], separators=(",", ":"))):
        assert secret not in caplog.text


def test_ballot_audit_events_hold_only_the_event_and_the_elector(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-12 test 6: BALLOT_TOKEN_ISSUED and BALLOT_ACCEPTED record the event type and the elector, and nothing else."""
    vote = cast(client, make_voter, sign_in)

    events = db_session.scalars(
        select(AuditLogEntry).where(AuditLogEntry.event_type.in_(("BALLOT_TOKEN_ISSUED", "BALLOT_ACCEPTED")))
    ).all()

    assert sorted(e.event_type for e in events) == ["BALLOT_ACCEPTED", "BALLOT_TOKEN_ISSUED"]
    assert all((e.actor, e.details) == (f"account:{vote['voter'].account_id}", {}) for e in events)


# ---------------------------------------------------------------
# Reading and exporting ballots
# ---------------------------------------------------------------


def test_export_and_bulk_reads_follow_ballot_id_not_arrival(db_session: Session, election, tmp_path: Path) -> None:
    """SR-12 test 7: ballots stored in descending id order come back in ascending id order, from the reader and the export."""
    election_id = election.election.id
    ids = sorted((uuid.uuid4() for _ in range(6)), reverse=True)
    for ballot_id in ids:  # arrival order: highest id first
        sealed = encrypt_ballot(ballot_payload(1, [1, 2]), ballot_id, election_id)
        db_session.execute(
            text("INSERT INTO ballots (id, election_id, encrypted_payload) VALUES (:i, :e, :p)"),
            {"i": ballot_id, "e": election_id, "p": sealed},
        )

    read = [row[0] for row in ballot_rows(db_session)]
    export_ballots(db_session, tmp_path / "ballots.jsonl")
    exported = [uuid.UUID(json.loads(line)["ballot_id"]) for line in (tmp_path / "ballots.jsonl").read_text().splitlines()]

    assert read == exported == sorted(ids)


def test_export_holds_only_ballot_fields_and_no_identity(
    client: TestClient, db_session: Session, make_voter, sign_in, tmp_path: Path
) -> None:
    """SR-12 test 8: each line has only ballot id, election id and the base64 ciphertext; no identity marker."""
    cast(client, make_voter, sign_in)
    out = tmp_path / "ballots.jsonl"

    assert export_ballots(db_session, out) == 1
    content = out.read_text(encoding="utf-8")
    line = json.loads(content)
    stored = db_session.execute(text("SELECT id, election_id, encrypted_payload FROM ballots")).one()

    assert set(line) == set(EXPORT_FIELDS)
    assert (line["ballot_id"], line["election_id"]) == (str(stored[0]), str(stored[1]))
    assert base64.b64decode(line["encrypted_payload_b64"]) == bytes(stored[2])
    assert not has_identity_marker(content, *identity_markers(db_session))
    assert check_files(db_session, ballot_identifiers(db_session), [out]).status == "PASS"


# ---------------------------------------------------------------
# The separation audit
# ---------------------------------------------------------------


def test_audit_passes_on_a_clean_database_after_a_vote(
    client: TestClient, db_session: Session, make_voter, sign_in, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """SR-12 test 9: after a real vote every check passes; with no --file, only the file check is SKIPPED."""
    cast(client, make_voter, sign_in)

    exit_code = run_main(db_session, tmp_path, monkeypatch)

    output = capsys.readouterr().out
    assert exit_code == 0
    assert [line.split()[0] for line in output.splitlines()[1:6]] == ["PASS", "PASS", "PASS", "PASS", "SKIPPED"]
    assert output.rstrip().endswith("SR-12 separation audit: PASS")


@pytest.mark.parametrize(
    "column",
    ["elector_id uuid", "client_ip text", "user_agent text", "cast_at timestamptz", "cast_time time", "seq serial"],
)
def test_audit_fails_on_a_forbidden_ballot_column(db_session: Session, column: str) -> None:
    """SR-12 test 10: an identity-like, time or serial column on a ballot table fails check b (added, then dropped)."""
    db_session.execute(text(f"ALTER TABLE ballots ADD COLUMN {column}"))
    try:
        check = check_ballot_columns(db_session)
    finally:
        db_session.execute(text(f"ALTER TABLE ballots DROP COLUMN {column.split()[0]}"))

    assert check.status == "FAIL" and check.reason.startswith(f"ballots.{column.split()[0]}")
    assert check_ballot_columns(db_session).status == "PASS"


def test_audit_fails_on_a_foreign_key_or_a_table_with_no_side(db_session: Session) -> None:
    """SR-12 test 11: a foreign key from a ballot table to an identity table, or an unclassified table, fails check a."""
    db_session.execute(text("ALTER TABLE ballot_tokens ADD CONSTRAINT sr12_test_link FOREIGN KEY (election_id) REFERENCES elections (id)"))
    try:
        linked = check_foreign_keys(db_session)
    finally:
        db_session.execute(text("ALTER TABLE ballot_tokens DROP CONSTRAINT sr12_test_link"))
    db_session.execute(text("CREATE TABLE sr12_test_new (x int)"))
    try:
        unclassified = check_foreign_keys(db_session)
    finally:
        db_session.execute(text("DROP TABLE sr12_test_new"))

    assert (linked.status, linked.reason) == ("FAIL", "foreign key(s) between the sides: ballot_tokens -> elections")
    assert unclassified.status == "FAIL" and "sr12_test_new" in unclassified.reason
    assert check_foreign_keys(db_session).status == "PASS"


@pytest.mark.parametrize("planted", ["token hash", "ballot id", "receipt"])
def test_audit_fails_on_a_ballot_identifier_planted_in_the_audit_log(
    client: TestClient, db_session: Session, make_voter, sign_in, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, planted: str
) -> None:
    """SR-12 test 12: a token hash, ballot id or receipt written into the audit log fails checks c and d, and the script exits 1."""
    vote = cast(client, make_voter, sign_in)
    token_hash = hash_token(vote["token"]).hex()
    value = {
        "token hash": token_hash,
        "ballot id": str(db_session.scalar(text("SELECT id FROM ballots"))),
        "receipt": vote["receipt"],
    }[planted]
    audit(db_session, "TEST_EVENT", actor="unknown", note=value)
    identifiers = ballot_identifiers(db_session)

    assert check_identity_tables(db_session, identifiers).reason == "ballot identifiers found in: audit_log (1)"
    assert check_logs(db_session, identifiers, tmp_path, tmp_path / "logs").status == "FAIL"
    assert run_main(db_session, tmp_path, monkeypatch) == 1
    output = capsys.readouterr().out
    assert output.rstrip().endswith("SR-12 separation audit: FAIL (2 checks)")
    assert token_hash not in output and vote["receipt"] not in output  # it never prints what it found


@pytest.mark.parametrize("where", ["log folder", "*.log file in the project"])
def test_audit_fails_on_a_ballot_id_in_a_log_file(
    client: TestClient, db_session: Session, make_voter, sign_in, tmp_path: Path, where: str
) -> None:
    """SR-12 test 13: a ballot id in a file in the log folder, or in any *.log file, fails check d."""
    cast(client, make_voter, sign_in)
    ballot_id = str(db_session.scalar(text("SELECT id FROM ballots")))
    log_dir, project = tmp_path / "logs", tmp_path / "project"
    target = log_dir / "server.txt" if where == "log folder" else project / "backend" / "api.log"
    target.parent.mkdir(parents=True)
    identifiers = ballot_identifiers(db_session)
    assert check_logs(db_session, identifiers, project, log_dir).status == "PASS"

    target.write_text(f"INFO stored ballot {ballot_id}\n", encoding="utf-8")

    assert check_logs(db_session, identifiers, project, log_dir).reason == f"ballot identifiers in: {target.name}"


# ---------------------------------------------------------------
# Backups and exports given with --file
# ---------------------------------------------------------------


def synthetic_dump(db_session: Session, extra_identity_line: str = "") -> str:
    """SR-12: a plain pg_dump-style file holding the real ballot-side rows inside their own COPY blocks."""
    ballot_id, election_id, _ = db_session.execute(text("SELECT id, election_id, encrypted_payload FROM ballots")).one()
    token_id, token_hash, receipt = db_session.execute(text("SELECT id, token_hash, receipt_reference FROM ballot_tokens")).one()
    roll_id = db_session.scalar(text("SELECT roll_id FROM voter_participation"))
    return "\n".join(
        [
            "-- PostgreSQL database dump",
            "CREATE TABLE public.ballots (id uuid NOT NULL, election_id uuid NOT NULL, encrypted_payload bytea NOT NULL);",
            "COPY public.ballots (id, election_id, encrypted_payload) FROM stdin;",
            f"{ballot_id}\t{election_id}\t\\\\x01aabbcc",
            "\\.",
            "COPY public.ballot_tokens (id, election_id, token_hash, receipt_reference) FROM stdin;",
            f"{token_id}\t{election_id}\t{token_hash}\t{receipt}",
            "\\.",
            "COPY public.voter_participation (roll_id, election_id, state) FROM stdin;",
            f"{roll_id}\t{election_id}\tvoted",
            *([extra_identity_line] if extra_identity_line else []),
            "\\.",
            "-- PostgreSQL database dump complete",
        ]
    )


def test_audit_passes_on_a_dump_with_ballot_ids_only_in_ballot_tables(
    client: TestClient, db_session: Session, make_voter, sign_in, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-12 test 14: ballot identifiers inside the ballot tables' own COPY blocks are where they belong."""
    cast(client, make_voter, sign_in)
    dump = tmp_path / "evoting.sql"
    dump.write_text(synthetic_dump(db_session), encoding="utf-8")

    assert check_files(db_session, ballot_identifiers(db_session), [dump]).status == "PASS"
    assert run_main(db_session, tmp_path, monkeypatch, "--file", str(dump)) == 0


def test_audit_fails_on_a_dump_with_a_ballot_id_outside_the_ballot_tables(
    client: TestClient, db_session: Session, make_voter, sign_in, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-12 test 15: the same dump with a ballot id in an identity table's data fails check e."""
    cast(client, make_voter, sign_in)
    ballot_id = str(db_session.scalar(text("SELECT id FROM ballots")))
    roll_id = db_session.scalar(text("SELECT roll_id FROM voter_participation"))
    dump = tmp_path / "identity.sql"
    dump.write_text(synthetic_dump(db_session, f"{roll_id}\t{ballot_id}\tvoted"), encoding="utf-8")

    check = check_files(db_session, ballot_identifiers(db_session), [dump])

    assert (check.status, check.reason) == ("FAIL", "identity.sql (1 ballot identifier(s) outside the ballot tables' data)")
    assert run_main(db_session, tmp_path, monkeypatch, "--file", str(dump)) == 1


def test_audit_fails_on_an_export_with_ballot_ids_and_an_elector_email(
    client: TestClient, db_session: Session, make_voter, sign_in, tmp_path: Path
) -> None:
    """SR-12 test 16: an export holding a ballot id together with an e-mail address, a username or an account id fails."""
    vote = cast(client, make_voter, sign_in)
    out = tmp_path / "ballots.jsonl"
    export_ballots(db_session, out)
    clean = out.read_text(encoding="utf-8")
    identifiers = ballot_identifiers(db_session)

    for marker in ("robin.reviewer@example.com", vote["voter"].username, str(vote["voter"].account_id)):
        out.write_text(clean.rstrip("\n")[:-1] + f', "contact": "{marker}"}}\n', encoding="utf-8")
        assert check_files(db_session, identifiers, [out]).reason == "ballots.jsonl (ballot identifiers together with identity data)"
