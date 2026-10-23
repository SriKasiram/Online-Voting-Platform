"""
SR-16: authentication, eligibility, privileged-access, configuration and ballot-box events are recorded
at once, in an append-only, hash-chained audit log, with allow-listed fields only: no ballot selection,
no raw token, and nothing linking an elector to their ballot.

The tests marked audit_capture perform one real action per category and check its entry. They run
monthly (.github/workflows/audit-capture.yml) and before each release: pytest -m audit_capture
"""

import hashlib
import json
import re
import secrets
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app import audit_events, rbac
from app.audit_events import CATEGORIES, EVENT_CATEGORIES, OUTCOMES, REASON_CODES, ROLES
from app.ballot_chain import CHECK_GROUPS, load_checkpoint_public_key
from app.config import BACKEND_DIR
from app.main import app
from app.models import AuditLogEntry, Ballot, BallotToken, ParticipationState, VoterParticipation
from app.request_id import REQUEST_ID_HEADER
from app.routers import ballot as ballot_router
from app.security import AUDIT_FORMAT_CURRENT, SESSION_COOKIE, AuditFieldError, audit, looks_secret, utc_now, verify_audit_chain
from app import participation
from scripts import audit_checkpoint, audit_separation, verify_audit
from scripts.ballot_definition import activate, build_payload, sign
from scripts.seal_ballots import load_private_key, seal_batch

LOGIN, VERIFY = "/api/auth/login", "/api/auth/verify"
SUBMIT = "/api/ballot/submit"

# SR-16: every column an entry written from SR-16 on may fill (details stays empty)
ALLOWED_COLUMNS = {
    "id",
    "created_at",
    "event_type",
    "actor",
    "category",
    "outcome",
    "role",
    "request_id",
    "batch_no",
    "count",
    "reason",
    # SR-18: the release version, filled by the result release events only
    "version",
    "format_version",
    "prev_hash",
    "hash",
}
WITHIN = timedelta(seconds=30)


def last_id(db: Session) -> int:
    db.expire_all()
    return db.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))


def entries_after(db: Session, after: int, event_type: str | None = None) -> list[AuditLogEntry]:
    db.expire_all()
    query = select(AuditLogEntry).where(AuditLogEntry.id > after).order_by(AuditLogEntry.id)
    if event_type:
        query = query.where(AuditLogEntry.event_type == event_type)
    return list(db.scalars(query))


def captured(db: Session, after: int, event_type: str) -> AuditLogEntry:
    found = entries_after(db, after, event_type)
    assert found, f"no {event_type} entry was written"
    return found[-1]


def check_entry(
    entry: AuditLogEntry,
    *,
    category: str,
    outcome: str,
    actor: str,
    role: str,
    started: datetime,
    response=None,
    reason: str | None = None,
    batch_no: int | None = None,
    count: int | None = None,
) -> None:
    """SR-16: the right category, outcome, actor and role, a request id, on time, and nothing off the list."""
    assert entry.category == category == EVENT_CATEGORIES[entry.event_type]
    assert (entry.outcome, entry.actor, entry.role) == (outcome, actor, role)
    assert (entry.reason, entry.batch_no, entry.count) == (reason, batch_no, count)
    assert isinstance(entry.request_id, uuid.UUID)
    if response is not None:
        assert str(entry.request_id) == response.headers[REQUEST_ID_HEADER]
    assert timedelta(0) <= entry.created_at - started <= WITHIN
    filled = {column.key for column in AuditLogEntry.__table__.columns if getattr(entry, column.key) is not None}
    # SR-18: new rows are written in the current format (3), which covers the release version too
    assert filled <= ALLOWED_COLUMNS and entry.details is None and entry.format_version == AUDIT_FORMAT_CURRENT


def login(client: TestClient, voter, password: str | None = None):
    return client.post(LOGIN, json={"username": voter.username, "password": password or voter.password})


def full_sign_in(client: TestClient, voter):
    """Both sign-in parts; returns the code step's response, whose X-Request-ID the entry must carry."""
    client.post("/api/auth/logout")
    login(client, voter)
    return client.post(VERIFY, json={"otp_code": voter.code()})


def vote(client: TestClient, voter) -> dict:
    full_sign_in(client, voter)
    issued = client.get("/api/ballot")
    paper = issued.json()
    ranking = [c["id"] for c in reversed(paper["candidates"])]
    accepted = client.post(SUBMIT, json={"ballot_token": paper["ballot_token"], "ranked_candidate_ids": ranking})
    assert accepted.status_code == 200
    return {"paper": paper, "ranking": ranking, "issued": issued, "accepted": accepted}


# ---------------------------------------------------------------
# Capture: one real action per category (pytest -m audit_capture)
# ---------------------------------------------------------------


@pytest.mark.audit_capture
def test_capture_authentication(client: TestClient, db_session: Session, make_voter) -> None:
    """SR-16 capture, authentication: a failed sign in with an unknown username, then a successful one."""
    voter = make_voter()
    before, started = last_id(db_session), utc_now()

    unknown = client.post(LOGIN, json={"username": "nobody.registered", "password": "not the password"})
    assert unknown.status_code == 401
    check_entry(
        captured(db_session, before, "auth_password_failed"),
        category="authentication", outcome="failure", actor="unknown", role="unknown", started=started, response=unknown,
    )

    verified = full_sign_in(client, voter)
    assert verified.status_code == 200
    check_entry(
        captured(db_session, before, "auth_login_success"),
        category="authentication", outcome="success", actor=f"account:{voter.account_id}", role="elector",
        started=started, response=verified,
    )
    assert voter.username not in "".join(str(e.actor) for e in entries_after(db_session, before))


@pytest.mark.audit_capture
def test_capture_eligibility(client: TestClient, db_session: Session, make_voter) -> None:
    """SR-16 capture, eligibility: an elector not enrolled is denied; a token is issued; a ballot is accepted."""
    refused, voter = make_voter(enrolled=False), make_voter()
    before, started = last_id(db_session), utc_now()

    full_sign_in(client, refused)
    denied = client.get("/api/ballot")
    assert denied.status_code == 403
    check_entry(
        captured(db_session, before, "ELIGIBILITY_DENIED"),
        category="eligibility", outcome="denied", actor=f"account:{refused.account_id}", role="elector",
        started=started, response=denied, reason="not_enrolled",
    )

    cast = vote(client, voter)
    for event_type, response in (("BALLOT_TOKEN_ISSUED", cast["issued"]), ("BALLOT_ACCEPTED", cast["accepted"])):
        check_entry(
            captured(db_session, before, event_type),
            category="eligibility", outcome="success", actor=f"account:{voter.account_id}", role="elector",
            started=started, response=response,
        )


@pytest.mark.audit_capture
def test_capture_privileged_access(client: TestClient, db_session: Session, make_voter, make_staff) -> None:
    """SR-16 capture, privileged access: an elector calls an admin route and is denied; a staff member signs in."""
    elector = make_voter()
    staff = make_staff("polling_official")
    before, started = last_id(db_session), utc_now()

    full_sign_in(client, elector)
    forbidden = client.get("/api/admin/turnout")
    assert forbidden.status_code == 403
    check_entry(
        captured(db_session, before, "AUTHZ_DENIED"),
        category="privileged_access", outcome="denied", actor=f"account:{elector.account_id}", role="elector",
        started=started, response=forbidden, reason=rbac.TURNOUT_READ,
    )

    staff_signed_in = full_sign_in(client, staff)
    assert staff_signed_in.status_code == 200
    check_entry(
        captured(db_session, before, "AUTH_PRIVILEGED_LOGIN_SUCCESS"),
        category="privileged_access", outcome="success", actor=f"account:{staff.account_id}", role="polling_official",
        started=started, response=staff_signed_in,
    )


@pytest.mark.audit_capture
def test_capture_configuration(db_session: Session, election, delegate_keys) -> None:
    """SR-16 capture, configuration: a ballot definition signed by one delegate only is rejected."""
    payload = build_payload(db_session, election.election, datetime(2000, 1, 1, tzinfo=UTC), datetime(2100, 1, 1, tzinfo=UTC))
    before, started = last_id(db_session), utc_now()

    assert activate(db_session, payload, [sign(delegate_keys["delegate_a"], payload)]) == "not_enough_delegates"

    entry = captured(db_session, before, "BALLOT_DEFINITION_REJECTED")
    check_entry(
        entry, category="configuration", outcome="rejected", actor="script", role="script", started=started,
        reason="not_enough_delegates",
    )
    recorded = json.dumps([entry.event_type, entry.reason, entry.actor])
    assert payload not in recorded and "signature" not in recorded


@pytest.mark.audit_capture
def test_capture_ballot_box(
    client: TestClient, db_session: Session, election, make_voter, checkpoint_keys, tmp_path: Path, audit_text
) -> None:
    """SR-16 capture, ballot box: a batch is sealed, and its entry holds only the batch number and the count."""
    cast = vote(client, make_voter())
    private_path, public_path = checkpoint_keys
    before, started = last_id(db_session), utc_now()

    result = seal_batch(
        db_session, election.election.id, True, load_private_key(private_path), load_checkpoint_public_key(public_path),
        tmp_path / "chain.jsonl",
    )

    assert result.reasons == []
    entry = captured(db_session, before, "BALLOT_BATCH_SEALED")
    check_entry(
        entry, category="ballot_box", outcome="success", actor="script", role="script", started=started,
        batch_no=1, count=1,
    )
    ballot_id = str(db_session.scalar(select(Ballot.id)))
    recorded = audit_text(before)
    assert ballot_id not in recorded and cast["paper"]["ballot_token"] not in recorded


# ---------------------------------------------------------------
# The catalogue
# ---------------------------------------------------------------

AUDIT_CALL = re.compile(r"\b(?:audit|log)\(\s*\w+,\s*\"(\w+)\"")
FAILURE_CALL = re.compile(r"record_failure\(\s*\w+,\s*[\w.]+(?: if [\w. ]+ else None)?,\s*\"(\w+)\"")


def event_types_in_code() -> set[str]:
    found: set[str] = set()
    for folder in ("app", "scripts"):
        for path in (BACKEND_DIR / folder).rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            found |= set(AUDIT_CALL.findall(source)) | set(FAILURE_CALL.findall(source))
    return found


def test_catalogue_covers_every_event_type_in_the_code() -> None:
    """SR-16: every event type written anywhere in app/ or scripts/ is catalogued, and nothing catalogued is unused."""
    used = event_types_in_code()

    assert len(used) >= 20
    assert used - set(EVENT_CATEGORIES) == set()
    assert set(EVENT_CATEGORIES) - used == set()


def test_catalogue_has_every_category_and_safe_codes() -> None:
    """SR-16: five categories, each used; the reason codes cover SR-05 and SR-13; no fixed value looks like a secret."""
    assert set(EVENT_CATEGORIES.values()) == CATEGORIES == {
        "authentication", "eligibility", "privileged_access", "configuration", "ballot_box",
    }
    assert OUTCOMES == {"success", "failure", "denied", "rejected"}
    assert ROLES == {"elector", "polling_official", "auditor", "script", "unknown"}
    assert rbac.ALL_PERMISSIONS <= REASON_CODES
    assert {code for codes in CHECK_GROUPS.values() for code in codes} <= REASON_CODES
    assert not [v for v in [*EVENT_CATEGORIES, *OUTCOMES, *ROLES, *REASON_CODES] if looks_secret(v)]


# ---------------------------------------------------------------
# The writer's allow-list
# ---------------------------------------------------------------

VALID = {"outcome": "success", "actor": "script", "role": "script"}


@pytest.mark.parametrize(
    ("event_type", "fields"),
    [
        ("NOT_AN_EVENT", VALID),
        ("auth_login_success", VALID | {"username": "voter.1"}),
        ("auth_login_success", VALID | {"ip": "203.0.113.9"}),
        ("auth_login_success", VALID | {"reason": "the voter chose Ortega first"}),
        ("auth_login_success", VALID | {"outcome": "maybe"}),
        ("auth_login_success", VALID | {"role": "superuser"}),
        ("auth_login_success", VALID | {"actor": "roll:1b4e28ba-2fa1-11d2-883f-0016d3cca427", "role": "elector"}),
        ("auth_login_success", VALID | {"actor": "203.0.113.9", "role": "unknown"}),
        ("auth_login_success", VALID | {"actor": "voter.1", "role": "elector"}),
        ("auth_login_success", VALID | {"actor": "unknown"}),  # an unknown actor must have the unknown role
        ("auth_login_success", VALID | {"reason": hashlib.sha256(b"token").hexdigest()}),  # 64 hex
        ("auth_login_success", VALID | {"reason": secrets.token_hex(16)}),  # 32 hex, a receipt reference
        ("auth_login_success", VALID | {"reason": secrets.token_urlsafe(32)}),  # a raw ballot token
        ("auth_login_success", VALID | {"actor": f"account:{hashlib.sha256(b'x').hexdigest()}", "role": "elector"}),
        ("BALLOT_BATCH_SEALED", VALID | {"batch_no": "3"}),
        ("BALLOT_BATCH_SEALED", VALID | {"count": 2.0}),
        ("BALLOT_BATCH_SEALED", VALID | {"count": True}),
        ("BALLOT_BATCH_SEALED", VALID | {"count": -1}),
        ("auth_login_success", VALID | {"request_id": "chosen-by-the-client"}),
    ],
)
def test_writer_refuses_anything_off_the_allow_list(db_session: Session, event_type: str, fields: dict) -> None:
    """SR-16: unknown events and fields, free text, values outside the sets, secret-shaped text: refused, nothing written."""
    before = last_id(db_session)

    with pytest.raises(AuditFieldError):
        audit(db_session, event_type, **fields)

    assert last_id(db_session) == before


def test_writer_accepts_the_allowed_forms(db_session: Session) -> None:
    """SR-16: an account actor with its role, a reason code and whole numbers are accepted, and chained."""
    account = f"account:{uuid.uuid4()}"
    audit(db_session, "ELIGIBILITY_DENIED", outcome="denied", actor=account, role="elector", reason="under_age")
    audit(db_session, "BALLOT_BATCH_SEALED", outcome="success", actor="script", role="script", batch_no=3, count=0)

    first, second = entries_after(db_session, last_id(db_session) - 2)
    assert (first.actor, first.reason, second.batch_no, second.count) == (account, "under_age", 3, 0)
    assert second.prev_hash == first.hash and verify_audit_chain(db_session)[1] is None


# ---------------------------------------------------------------
# Fail closed: the entry is part of the change
# ---------------------------------------------------------------


def failing_writer(event_type: str):
    """SR-16: the real writer, except that it fails for one event type."""

    def write(db, written_type, **fields):
        if written_type == event_type:
            raise RuntimeError("the audit log cannot be written")
        return audit(db, written_type, **fields)

    return write


def server(client: TestClient) -> TestClient:
    """The same signed-in session, but answering a crash with a 500 instead of raising it."""
    return TestClient(app, base_url="https://testserver", raise_server_exceptions=False, cookies={SESSION_COOKIE: client.cookies[SESSION_COOKIE]})


def test_no_token_is_issued_if_its_entry_cannot_be_written(
    client: TestClient, db_session: Session, make_voter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-16 fail closed: the token issue's entry fails, so no token and no participation row exist."""
    full_sign_in(client, make_voter())
    monkeypatch.setattr(ballot_router, "audit", failing_writer("BALLOT_TOKEN_ISSUED"))

    response = server(client).get("/api/ballot")

    assert response.status_code == 500 and "ballot_token" not in response.text
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(BallotToken)) == 0
    assert db_session.scalar(select(func.count()).select_from(VoterParticipation)) == 0


def test_no_ballot_is_accepted_if_its_entry_cannot_be_written(
    client: TestClient, db_session: Session, make_voter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-16 fail closed: the acceptance entry fails, so no ballot, the token unused and the elector still issued."""
    full_sign_in(client, make_voter())
    paper = client.get("/api/ballot").json()
    monkeypatch.setattr(ballot_router, "audit", failing_writer("BALLOT_ACCEPTED"))

    response = server(client).post(
        SUBMIT, json={"ballot_token": paper["ballot_token"], "ranked_candidate_ids": [c["id"] for c in paper["candidates"]]}
    )

    assert response.status_code == 500 and "receipt_id" not in response.text
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(Ballot)) == 0
    assert db_session.scalars(select(BallotToken.consumed)).one() is False
    assert db_session.scalars(select(VoterParticipation.state)).one() == ParticipationState.ISSUED


def test_no_reset_happens_if_its_entry_cannot_be_written(
    client: TestClient, db_session: Session, make_voter, make_staff, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-16 fail closed: the elector reset's entry fails, so the elector stays issued."""
    elector = make_voter()
    full_sign_in(client, elector)
    client.get("/api/ballot")
    roll_id = db_session.scalars(select(VoterParticipation.roll_id)).one()
    full_sign_in(client, make_staff("polling_official"))
    monkeypatch.setattr(participation, "audit", failing_writer("ELECTOR_RESET"))

    response = server(client).post(f"/api/admin/electors/{roll_id}/reset")

    assert response.status_code == 500
    db_session.expire_all()
    assert db_session.scalars(select(VoterParticipation.state)).one() == ParticipationState.ISSUED


# ---------------------------------------------------------------
# Append-only
# ---------------------------------------------------------------


@pytest.mark.parametrize("statement", ["UPDATE audit_log SET outcome = 'success'", "DELETE FROM audit_log"])
def test_database_refuses_update_and_delete(db_session: Session, statement: str) -> None:
    """SR-16: the trigger refuses UPDATE and DELETE on every row; INSERT through the writer still works."""
    audit(db_session, "auth_rate_limited", outcome="denied", actor="unknown", role="unknown")
    count = db_session.scalar(select(func.count()).select_from(AuditLogEntry))

    savepoint = db_session.begin_nested()
    with pytest.raises(DBAPIError, match=r"the audit log is append-only \(SR-16\)"):
        db_session.execute(text(statement))
    savepoint.rollback()

    audit(db_session, "auth_rate_limited", outcome="denied", actor="unknown", role="unknown")
    assert db_session.scalar(select(func.count()).select_from(AuditLogEntry)) == count + 1


# ---------------------------------------------------------------
# Checkpoints and verify_audit
# ---------------------------------------------------------------


@contextmanager
def trigger_off(db: Session) -> Iterator[None]:
    """SR-16: tampering as only a database owner could; on again afterwards (and the test rolls back)."""
    db.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    try:
        yield
    finally:
        db.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))


@pytest.fixture
def signed_log(db_session: Session, checkpoint_keys, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    SR-16: six entries with a gap in their ids after the second (room for an inserted one), and
    signed checkpoints after the fourth and the sixth, in this test's own checkpoint folder.
    """
    monkeypatch.setattr(audit_checkpoint, "audit_checkpoint_file", lambda: tmp_path / "audit.jsonl")
    monkeypatch.setattr(verify_audit, "audit_checkpoint_file", lambda: tmp_path / "audit.jsonl")
    private_path, public_path = checkpoint_keys
    private_key, public_key = load_private_key(private_path), load_checkpoint_public_key(public_path)
    before = last_id(db_session)
    for n in range(6):
        if n == 2:
            db_session.execute(text("SELECT nextval(pg_get_serial_sequence('audit_log', 'id'))"))
        audit(db_session, "BALLOT_BATCH_SEALED", outcome="success", actor="script", role="script", batch_no=n + 1, count=10)
        if n in (3, 5):
            audit_checkpoint.sign_audit_checkpoint(db_session, private_key, public_key, tmp_path / "audit.jsonl")
    entries = entries_after(db_session, before)
    return {"entries": entries, "public_key": public_key, "path": tmp_path / "audit.jsonl"}


def failing_checks(db: Session, signed_log) -> set[str]:
    results = verify_audit.verify_audit(db, signed_log["public_key"], signed_log["path"])
    return {check for check, problem in results.items() if problem is not None}


def run_verify_main(db: Session, monkeypatch: pytest.MonkeyPatch, capsys) -> tuple[int, str]:
    monkeypatch.setattr(verify_audit, "SessionLocal", lambda: nullcontext(db))
    code = verify_audit.main([])
    return code, capsys.readouterr().out


def test_verify_audit_passes_on_a_clean_log_with_checkpoints(
    db_session: Session, signed_log, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """SR-16: a clean log with two signed checkpoints passes every check, and the script exits 0."""
    lines = signed_log["path"].read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["entry_count"] for line in lines] == [len(signed_log["entries"]) - 2, len(signed_log["entries"])]
    assert failing_checks(db_session, signed_log) == set()

    code, output = run_verify_main(db_session, monkeypatch, capsys)

    assert code == 0
    assert [line.split()[0] for line in output.splitlines()[1:4]] == ["PASS", "PASS", "PASS"]
    assert output.rstrip().endswith("SR-16 audit verification: PASS")


def swap_contents(db: Session, first: AuditLogEntry, second: AuditLogEntry) -> None:
    columns = ["created_at", "event_type", "actor", "category", "outcome", "role", "request_id", "batch_no", "count", "reason", "prev_hash", "hash"]
    values = {f"{c}_{n}": getattr(entry, c) for n, entry in ((1, first), (2, second)) for c in columns}
    # prev_hash is unique, so park one row's value first
    db.execute(text("UPDATE audit_log SET prev_hash = :parked WHERE id = :id"), {"parked": secrets.token_bytes(32), "id": first.id})
    for target, source in ((second.id, 1), (first.id, 2)):
        assignments = ", ".join(f"{c} = :{c}_{source}" for c in columns)
        db.execute(text(f"UPDATE audit_log SET {assignments} WHERE id = :target"), values | {"target": target})


@pytest.mark.parametrize("tampering", ["modified", "deleted", "swapped", "inserted", "truncated"])
def test_verify_audit_detects_tampering(
    db_session: Session, signed_log, tampering: str, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """SR-16: a modified, deleted, swapped or inserted entry, or a log cut below a checkpoint, fails and exits 1."""
    entries = signed_log["entries"]
    with trigger_off(db_session):
        if tampering == "modified":
            db_session.execute(text("UPDATE audit_log SET count = 11 WHERE id = :id"), {"id": entries[1].id})
        elif tampering == "deleted":
            db_session.execute(text("DELETE FROM audit_log WHERE id = :id"), {"id": entries[3].id})
        elif tampering == "swapped":
            swap_contents(db_session, entries[3], entries[4])
        elif tampering == "inserted":
            # Into the gap the fixture left after the second entry
            db_session.execute(
                text(
                    "INSERT INTO audit_log (id, created_at, event_type, actor, category, outcome, role, request_id, "
                    "format_version, prev_hash, hash) VALUES (:id, now(), 'ROLL_VERIFIED', 'unknown', 'configuration', "
                    "'success', 'unknown', gen_random_uuid(), 2, :prev, :hash)"
                ),
                {"id": entries[1].id + 1, "prev": secrets.token_bytes(32), "hash": secrets.token_bytes(32)},
            )
        else:  # truncated: the last two entries, so what is left still links up
            db_session.execute(text("DELETE FROM audit_log WHERE id >= :id"), {"id": entries[4].id})

    failed = failing_checks(db_session, signed_log)
    code, output = run_verify_main(db_session, monkeypatch, capsys)

    expected_chain_failure = tampering != "truncated"
    assert (verify_audit.CHAIN in failed) is expected_chain_failure
    if tampering in ("deleted", "inserted", "truncated"):
        assert verify_audit.AGAINST_LOG in failed
    assert code == 1 and "FAIL" in output and output.rstrip().endswith(f"FAIL ({len(failed)} checks)")


def test_verify_audit_fails_without_checkpoints_and_a_checkpoint_is_refused_on_a_bad_chain(
    db_session: Session, checkpoint_keys, tmp_path: Path
) -> None:
    """SR-16: no checkpoint file fails b and c; a tampered chain is never signed; an altered checkpoint line fails b."""
    private_path, public_path = checkpoint_keys
    private_key, public_key = load_private_key(private_path), load_checkpoint_public_key(public_path)
    path = tmp_path / "audit.jsonl"
    for _ in range(2):
        audit(db_session, "auth_rate_limited", outcome="denied", actor="unknown", role="unknown")

    results = verify_audit.verify_audit(db_session, public_key, path)
    assert {c for c, p in results.items() if p} == {verify_audit.SIGNATURES, verify_audit.AGAINST_LOG}

    audit_checkpoint.sign_audit_checkpoint(db_session, private_key, public_key, path)
    line = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps(line | {"entry_count": line["entry_count"] - 1}) + "\n", encoding="utf-8")
    assert verify_audit.verify_audit(db_session, public_key, path)[verify_audit.SIGNATURES] == "bad_checkpoint_signature"

    last = entries_after(db_session, 0)[-1]
    with trigger_off(db_session):
        db_session.execute(text("UPDATE audit_log SET outcome = 'success' WHERE id = :id"), {"id": last.id})
    with pytest.raises(audit_checkpoint.CheckpointRefused, match="does not verify"):
        audit_checkpoint.sign_audit_checkpoint(db_session, private_key, public_key, tmp_path / "fresh.jsonl")
    assert not (tmp_path / "fresh.jsonl").exists()


def test_rows_written_before_sr16_still_verify(db_session: Session) -> None:
    """SR-16: a version 1 row (the SR-01 formula, free-form details) verifies, and a version 2 row chains after it."""
    prev = db_session.scalar(select(AuditLogEntry.hash).order_by(AuditLogEntry.id.desc()).limit(1)) or bytes(32)
    created_at = utc_now()
    details = {"records": 2}
    old_body = {"created_at": created_at.isoformat(), "event_type": "ROLL_VERIFIED", "actor": "unknown", "details": details}
    db_session.add(
        AuditLogEntry(
            created_at=created_at,
            event_type="ROLL_VERIFIED",
            actor="unknown",
            details=details,
            format_version=1,
            prev_hash=prev,
            hash=hashlib.sha256(prev + json.dumps(old_body, sort_keys=True).encode()).digest(),
        )
    )
    db_session.flush()
    audit(db_session, "ROLL_VERIFIED", outcome="success", actor="unknown", role="unknown", count=2)

    assert verify_audit_chain(db_session)[1] is None
    old = db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.format_version == 1)).one()
    with trigger_off(db_session):
        db_session.execute(text("UPDATE audit_log SET details = '{\"records\": 3}' WHERE id = :id"), {"id": old.id})
    db_session.expire_all()
    assert verify_audit_chain(db_session)[1] == old.id


# ---------------------------------------------------------------
# No link between an elector and a ballot
# ---------------------------------------------------------------


def test_after_a_vote_no_audit_row_holds_a_ballot_value_and_request_ids_stay_identity_side(
    client: TestClient, db_session: Session, make_voter, tmp_path: Path, audit_text
) -> None:
    """SR-16: no token, token hash, receipt, receipt hash, ballot id or selection in the log; SR-12 still passes."""
    before = last_id(db_session)
    voter = make_voter()
    cast = vote(client, voter)
    token, receipt = cast["paper"]["ballot_token"], cast["accepted"].json()["receipt_id"]
    ballot_id = str(db_session.scalar(select(Ballot.id)))

    recorded = audit_text(before)
    forbidden = [
        token,
        hashlib.sha256(token.encode()).hexdigest(),
        receipt,
        hashlib.sha256(receipt.encode()).hexdigest(),
        ballot_id,
        json.dumps(cast["ranking"]),
        "ranked_candidate_ids",
        *(c["surname"] for c in cast["paper"]["candidates"]),
        voter.username,
    ]
    assert [value for value in forbidden if value in recorded] == []
    assert {c.status for c in audit_separation.run_audit(db_session, [], tmp_path, tmp_path / "logs")} <= {"PASS", "SKIPPED"}

    request_ids = {cast["issued"].headers[REQUEST_ID_HEADER], cast["accepted"].headers[REQUEST_ID_HEADER]}
    assert request_ids <= {str(e.request_id) for e in entries_after(db_session, before)}
    ballot_side = " ".join(
        row
        for table in ("ballots", "ballot_tokens", "ballot_chain")
        for row in db_session.scalars(text(f"SELECT row_to_json(t)::text FROM {table} AS t"))
    )
    assert [rid for rid in request_ids if rid in ballot_side] == []


# ---------------------------------------------------------------
# Request ids
# ---------------------------------------------------------------


def test_every_response_has_its_own_request_id_and_a_client_one_is_ignored(client: TestClient, db_session: Session) -> None:
    """SR-16: X-Request-ID on every response, different each time; one sent by the client is never used."""
    first, second = client.get("/api/health"), client.get("/api/health")
    assert first.headers[REQUEST_ID_HEADER] != second.headers[REQUEST_ID_HEADER]
    assert all(uuid.UUID(r.headers[REQUEST_ID_HEADER]).version == 4 for r in (first, second))

    planted = str(uuid.uuid4())
    before = last_id(db_session)
    refused = client.post(LOGIN, json={"username": "nobody.registered", "password": "x"}, headers={REQUEST_ID_HEADER: planted})

    assert refused.headers[REQUEST_ID_HEADER] != planted
    entry = captured(db_session, before, "auth_password_failed")
    assert str(entry.request_id) == refused.headers[REQUEST_ID_HEADER] != planted
    # SR-09 and SR-10 still apply alongside it
    assert refused.headers["cache-control"] == "no-store" and "max-age" in refused.headers["strict-transport-security"]


def test_entries_outside_a_request_get_their_own_id(db_session: Session) -> None:
    """SR-16: scripts and start-up have no request, so each of their entries gets a fresh random id."""
    before = last_id(db_session)
    for _ in range(2):
        audit(db_session, "ROLL_VERIFIED", outcome="success", actor=audit_events.UNKNOWN, role=audit_events.UNKNOWN, count=0)

    ids = [entry.request_id for entry in entries_after(db_session, before)]
    assert len(set(ids)) == 2 and all(rid.version == 4 for rid in ids)
