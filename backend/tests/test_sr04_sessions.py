"""
SR-04: server-side sessions named by a 256-bit random identifier. A session
expires SESSION_MINUTES after issue whatever the activity, can be extended at
most MAX_SESSION_EXTENSIONS times with a new identifier each time, and is
accepted only where it belongs.
"""

import base64
import hashlib
import json
import threading
from collections.abc import Iterator
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, delete, func, select, text
from sqlalchemy.orm import Session

from app.config import Settings, settings
from app.deps import get_db
from app.main import app
from app.models import Account, AccountRole, AuditLogEntry, AuthSession, SessionStage
from app.security import SESSION_COOKIE, encrypt, hash_password, hash_token, new_token, new_totp_secret, utc_now

EXTEND = "/api/auth/extend"
NOT_SIGNED_IN = (401, {"detail": "not_signed_in"})
SIGN_IN_FAILED = (401, {"detail": "invalid_credentials"})
LIMIT = (409, {"detail": "extension_limit"})
SR04_SETTINGS = ("session_minutes", "max_session_extensions", "mfa_pending_minutes", "post_ballot_session_seconds")


@pytest.fixture(autouse=True)
def shipped_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-04: these tests check the shipped defaults, whatever backend/.env sets."""
    for name in SR04_SETTINGS:
        monkeypatch.setattr(settings, name, Settings.model_fields[name].default)


def as_session(token: str) -> TestClient:
    """A client that presents exactly this identifier and nothing else."""
    return TestClient(app, base_url="https://testserver", headers={"cookie": f"{SESSION_COOKIE}={token}"})


def outcome(response) -> tuple[int, dict]:
    return response.status_code, response.json()


def login(client: TestClient, voter):
    return client.post("/api/auth/login", json={"username": voter.username, "password": voter.password})


def verify(client: TestClient, voter):
    return client.post("/api/auth/verify", json={"otp_code": voter.code()})


def row(db_session: Session, token: str) -> AuthSession | None:
    db_session.expire_all()
    return db_session.get(AuthSession, hash_token(token))


def submit(client: TestClient, ballot: dict):
    return client.post(
        "/api/ballot/submit",
        json={"ballot_token": ballot["ballot_token"], "ranked_candidate_ids": [c["id"] for c in ballot["candidates"]]},
    )


# ---------------------------------------------------------------
# Fixed expiry
# ---------------------------------------------------------------


def test_session_expires_ten_minutes_after_issue_whatever_the_activity(
    client: TestClient, db_session: Session, make_voter, sign_in, clock
) -> None:
    """SR-04 test 1: accepted at 9:59, refused at 10:01, and the requests in between never extend it."""
    sign_in(make_voter())
    token, issued = client.cookies[SESSION_COOKIE], clock.now

    for minutes in (1, 4, 8):
        clock.now = issued + timedelta(minutes=minutes)
        assert as_session(token).get("/api/ballot").status_code != 401
    clock.now = issued + timedelta(minutes=9, seconds=59)
    assert as_session(token).get("/api/ballot").status_code != 401
    assert row(db_session, token).expires_at == issued + timedelta(minutes=10)

    clock.now = issued + timedelta(minutes=10, seconds=1)
    assert outcome(as_session(token).get("/api/ballot")) == NOT_SIGNED_IN


def test_pending_session_ends_after_two_minutes_and_works_once(client: TestClient, make_voter, clock) -> None:
    """SR-04 test 2: the code step is refused 2:01 after the password step, and a used pending session is dead."""
    voter = make_voter()
    login(client, voter)
    clock.advance(minutes=2, seconds=1)
    assert outcome(verify(client, voter)) == SIGN_IN_FAILED

    login(client, voter)
    pending = client.cookies[SESSION_COOKIE]
    clock.advance(minutes=1, seconds=59)
    assert verify(client, voter).status_code == 200
    clock.advance(seconds=30)
    assert outcome(verify(as_session(pending), voter)) == SIGN_IN_FAILED


def test_each_stage_is_accepted_only_where_it_belongs(client: TestClient, make_voter, clock) -> None:
    """SR-04 test 3: a pending session opens no voting route or extension; a signed-in one cannot do the code step."""
    voter = make_voter()
    login(client, voter)
    pending = client.cookies[SESSION_COOKIE]
    for method, path, body in [
        ("GET", "/api/ballot", None),
        ("POST", "/api/ballot/submit", {"ballot_token": "any", "ranked_candidate_ids": [1]}),
        ("POST", EXTEND, None),
    ]:
        assert as_session(pending).request(method, path, json=body).status_code == 401, path

    assert verify(client, voter).status_code == 200
    signed_in = client.cookies[SESSION_COOKIE]
    clock.advance(seconds=30)  # a fresh code, so only the session's stage decides
    assert outcome(verify(as_session(signed_in), voter)) == SIGN_IN_FAILED


# ---------------------------------------------------------------
# Extension and rotation
# ---------------------------------------------------------------


def test_two_extensions_each_rotate_the_identifier(
    client: TestClient, db_session: Session, make_voter, sign_in
) -> None:
    """SR-04 test 4: both extensions succeed with a new identifier, and every old identifier is refused."""
    sign_in(make_voter())
    tokens = [client.cookies[SESSION_COOKIE]]
    for _ in range(2):
        assert client.post(EXTEND).status_code == 204
        tokens.append(client.cookies[SESSION_COOKIE])

    assert len(set(tokens)) == 3
    for old in tokens[:2]:
        assert outcome(as_session(old).get("/api/ballot")) == NOT_SIGNED_IN
        assert outcome(as_session(old).post(EXTEND)) == NOT_SIGNED_IN
    assert as_session(tokens[2]).get("/api/ballot").status_code == 200
    assert row(db_session, tokens[2]).extensions == 2


def test_third_extension_is_refused_and_the_total_stays_within_thirty_minutes(
    client: TestClient, db_session: Session, make_voter, sign_in, clock
) -> None:
    """SR-04 test 5: extending as late as possible twice, then a third time: 409, and no more than 30 minutes."""
    sign_in(make_voter())
    issued = clock.now
    for _ in range(2):
        clock.advance(minutes=9, seconds=59)
        assert client.post(EXTEND).status_code == 204
    clock.advance(minutes=9, seconds=59)

    assert outcome(client.post(EXTEND)) == LIMIT
    token = client.cookies[SESSION_COOKIE]
    assert row(db_session, token).expires_at - issued <= timedelta(minutes=30)
    clock.now = issued + timedelta(minutes=30, seconds=1)
    assert outcome(as_session(token).get("/api/ballot")) == NOT_SIGNED_IN


def test_extension_after_expiry_is_refused(client: TestClient, make_voter, sign_in, clock) -> None:
    """SR-04 test 6: an expired session cannot be extended back to life."""
    sign_in(make_voter())
    clock.advance(minutes=10, seconds=1)

    assert outcome(client.post(EXTEND)) == NOT_SIGNED_IN


def test_logged_out_identifier_is_refused(client: TestClient, db_session: Session, make_voter, sign_in) -> None:
    """SR-04 test 7: after sign out the identifier opens nothing and the row is gone."""
    sign_in(make_voter())
    token = client.cookies[SESSION_COOKIE]
    client.post("/api/auth/logout")

    assert outcome(as_session(token).get("/api/ballot")) == NOT_SIGNED_IN
    assert outcome(as_session(token).post(EXTEND)) == NOT_SIGNED_IN
    assert row(db_session, token) is None


def test_session_ends_soon_after_a_ballot_is_accepted(
    client: TestClient, db_session: Session, make_voter, sign_in, clock
) -> None:
    """SR-04 test 8: within 60 seconds of acceptance the session ends; no extension, and a safe retry still works."""
    sign_in(make_voter())
    ballot = client.get("/api/ballot").json()
    accepted_at = clock.now
    receipt = submit(client, ballot).json()
    token = client.cookies[SESSION_COOKIE]

    cut = row(db_session, token)
    assert cut.expires_at <= accepted_at + timedelta(seconds=60) and cut.extensions == 2
    assert outcome(client.post(EXTEND)) == LIMIT
    clock.advance(seconds=30)
    assert outcome(submit(client, ballot)) == (200, receipt)
    assert row(db_session, token).expires_at == cut.expires_at  # the retry did not lengthen it

    clock.advance(seconds=31)
    assert outcome(submit(client, ballot)) == NOT_SIGNED_IN


# ---------------------------------------------------------------
# The identifier itself
# ---------------------------------------------------------------


@pytest.mark.parametrize("change", ["random", "truncated", "modified"])
def test_altered_identifiers_are_refused_and_the_cookie_keeps_its_flags(
    client: TestClient, make_voter, sign_in, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """SR-04 test 9: a made-up, shortened or changed identifier is refused; the cookie stays Secure, HttpOnly, Strict."""
    monkeypatch.setattr(settings, "cookie_secure", True)
    signed_in = sign_in(make_voter())
    real = client.cookies[SESSION_COOKIE]
    bad = {"random": new_token(), "truncated": real[:-1], "modified": real[:-1] + ("A" if real[-1] != "A" else "B")}

    assert outcome(as_session(bad[change]).get("/api/ballot")) == NOT_SIGNED_IN
    assert outcome(as_session(bad[change]).post(EXTEND)) == NOT_SIGNED_IN
    extended = client.post(EXTEND)
    for response in (signed_in, extended):
        flags = response.headers["set-cookie"].lower()
        assert all(flag in flags for flag in ("secure", "httponly", "samesite=strict", "path=/"))


def test_identifiers_are_256_bit_hashed_and_never_reused(
    client: TestClient, db_session: Session, make_voter
) -> None:
    """SR-04 test 10: 32 random bytes each, a new one at every step, and only the SHA-256 is stored."""
    voter = make_voter()
    login(client, voter)
    tokens = [client.cookies[SESSION_COOKIE]]
    verify(client, voter)
    tokens.append(client.cookies[SESSION_COOKIE])
    for _ in range(2):
        client.post(EXTEND)
        tokens.append(client.cookies[SESSION_COOKIE])

    assert len(set(tokens)) == 4
    assert all(len(base64.urlsafe_b64decode(t + "=")) == 32 for t in tokens)
    stored = db_session.scalars(select(AuthSession).where(AuthSession.account_id == voter.account_id)).one()
    assert stored.session_id_hash == hashlib.sha256(tokens[-1].encode()).digest()
    for table in ("sessions", "audit_log"):
        for token in tokens:
            found = db_session.scalar(
                text(f"SELECT count(*) FROM {table} AS r WHERE strpos(r::text, :t) > 0"), {"t": token}
            )
            assert found == 0, table


def test_new_sign_in_clears_expired_sessions(client: TestClient, db_session: Session, make_voter, sign_in, clock) -> None:
    """SR-04: starting a sign in deletes expired session rows, so the table does not grow."""
    first, second = make_voter(), make_voter()
    sign_in(first)
    old = client.cookies[SESSION_COOKIE]
    clock.advance(minutes=10, seconds=1)

    login(client, second)

    assert row(db_session, old) is None


def test_extension_audit_events_hold_no_identifiers(
    client: TestClient, db_session: Session, make_voter, sign_in, clock
) -> None:
    """SR-04 test 12: SESSION_EXTENDED and SESSION_EXTENSION_REFUSED (limit, expired), by account, without identifiers."""
    before = db_session.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))
    voter = make_voter()
    sign_in(voter)
    tokens = [client.cookies[SESSION_COOKIE]]
    for _ in range(2):
        client.post(EXTEND)
        tokens.append(client.cookies[SESSION_COOKIE])
    client.post(EXTEND)
    clock.advance(minutes=10, seconds=1)
    client.post(EXTEND)

    rows = db_session.scalars(
        select(AuditLogEntry).where(AuditLogEntry.id > before, AuditLogEntry.event_type.like("SESSION_%"))
    ).all()
    assert [(r.event_type, r.details) for r in rows] == [
        ("SESSION_EXTENDED", {}),
        ("SESSION_EXTENDED", {}),
        ("SESSION_EXTENSION_REFUSED", {"reason": "limit"}),
        ("SESSION_EXTENSION_REFUSED", {"reason": "expired"}),
    ]
    assert {r.actor for r in rows} == {f"account:{voter.account_id}"}
    recorded = json.dumps([[r.event_type, r.actor, r.details] for r in rows])
    assert [t for t in tokens if t in recorded or hash_token(t).hex() in recorded] == []


def test_settings_defaults() -> None:
    """SR-04: 10-minute sessions, 2 extensions, a 2-minute code step and 60 seconds after a ballot."""
    assert {name: Settings.model_fields[name].default for name in SR04_SETTINGS} == {
        "session_minutes": 10,
        "max_session_extensions": 2,
        "mfa_pending_minutes": 2,
        "post_ballot_session_seconds": 60,
    }


# ---------------------------------------------------------------
# Real concurrency
# ---------------------------------------------------------------


def test_ten_simultaneous_extensions_with_one_identifier_allow_one(engine: Engine) -> None:
    """
    SR-04 test 11: 10 extension requests carrying the same identifier at the same
    moment: exactly one rotates the session, the rest get 401. Needs real,
    separate transactions, so it commits its own rows and removes them afterwards.
    """

    def real_db() -> Iterator[Session]:
        with Session(engine) as session:
            yield session

    token = new_token()
    with Session(engine) as setup:
        before = setup.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))
        account = Account(
            username="sr04.parallel",
            password_hash=hash_password("a long enough password"),
            role=AccountRole.AUDITOR,  # SR-05: an account with no roll entry must be staff now
            totp_secret_enc=encrypt(new_totp_secret(), "accounts.totp_secret"),
        )
        setup.add(account)
        setup.flush()
        setup.add(
            AuthSession(
                session_id_hash=hash_token(token),
                account_id=account.id,
                stage=SessionStage.AUTHENTICATED,
                expires_at=utc_now() + timedelta(minutes=10),
            )
        )
        setup.commit()
        account_id = account.id

    barrier = threading.Barrier(10)
    responses: list = []

    def extend_once() -> None:
        api = as_session(token)
        barrier.wait()
        responses.append(api.post(EXTEND))

    app.dependency_overrides[get_db] = real_db
    try:
        threads: list[threading.Thread] = [threading.Thread(target=extend_once) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sorted(r.status_code for r in responses) == [204] + [401] * 9
        winner = next(r for r in responses if r.status_code == 204).cookies[SESSION_COOKIE]
        with Session(engine) as check:
            stored = check.scalars(select(AuthSession).where(AuthSession.account_id == account_id)).one()
            assert (stored.session_id_hash, stored.extensions) == (hash_token(winner), 1)
    finally:
        app.dependency_overrides.clear()
        with Session(engine) as cleanup:
            cleanup.execute(delete(AuditLogEntry).where(AuditLogEntry.id > before))
            cleanup.execute(delete(AuthSession).where(AuthSession.account_id == account_id))
            cleanup.execute(delete(Account).where(Account.id == account_id))
            cleanup.commit()
