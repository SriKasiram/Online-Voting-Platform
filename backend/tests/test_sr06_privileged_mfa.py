"""
SR-06: every privileged sign in (any role but elector) needs the password and
a code from the authenticator app (TOTP), and gives a 10-minute session that
cannot be extended. Elector sign in is unchanged.
"""

import uuid
from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from helpers import account_row, last_id, outcome
from app.config import Settings, settings
from app.models import AuditLogEntry, AuthSession, SessionStage
from app.security import SESSION_COOKIE, decrypt, hash_token

EXTEND = "/api/auth/extend"
ADMIN_ROUTES = [
    ("GET", "/api/admin/turnout"),
    ("POST", f"/api/admin/electors/{uuid.uuid4()}/reset"),
    ("GET", "/api/admin/audit-log"),
    ("GET", "/api/admin/audit-log/verify"),
]
SIGN_IN_FAILED = (401, {"detail": "invalid_credentials"})
LIMIT = (409, {"detail": "extension_limit"})
WRONG_PASSWORD = "not the password"


@pytest.fixture(autouse=True)
def shipped_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-06: these tests check the shipped session and lockout defaults, whatever backend/.env sets."""
    for name in ("session_minutes", "max_session_extensions", "mfa_pending_minutes", "max_failed_attempts"):
        monkeypatch.setattr(settings, name, Settings.model_fields[name].default)


def login(client: TestClient, user, password: str | None = None):
    return client.post("/api/auth/login", json={"username": user.username, "password": password or user.password})


def verify(client: TestClient, code: str):
    return client.post("/api/auth/verify", json={"otp_code": code})


def code_at(user, clock, steps: int = 0) -> str:
    return pyotp.TOTP(user.totp_secret).at(clock.now + timedelta(seconds=30 * steps))


def wrong_code(user, clock) -> str:
    valid = {code_at(user, clock, steps) for steps in (-1, 0, 1)}
    return next(c for c in ("000000", "111111", "222222", "333333") if c not in valid)


def session_row(db_session: Session, token: str) -> AuthSession:
    db_session.expire_all()
    return db_session.get_one(AuthSession, hash_token(token))


def events(db_session: Session, before: int, *types: str) -> list[AuditLogEntry]:
    query = select(AuditLogEntry).where(AuditLogEntry.id > before).order_by(AuditLogEntry.id)
    return list(db_session.scalars(query.where(AuditLogEntry.event_type.in_(types)) if types else query))


def test_staff_sign_in_needs_the_password_and_the_code(
    client: TestClient, db_session: Session, election, make_staff, clock
) -> None:
    """SR-06 test 1: password then code: a signed-in session, the role, admin access and a privileged audit entry."""
    before = last_id(db_session)
    official = make_staff("polling_official")

    assert login(client, official).status_code == 204
    verified = verify(client, code_at(official, clock))

    assert (verified.status_code, verified.json()) == (200, {"role": "polling_official"})
    assert session_row(db_session, client.cookies[SESSION_COOKIE]).stage == SessionStage.AUTHENTICATED
    assert client.get("/api/admin/turnout").status_code == 200
    signed_in = events(db_session, before, "auth_login_success", "AUTH_PRIVILEGED_LOGIN_SUCCESS")
    assert [(e.event_type, e.actor) for e in signed_in] == [
        ("auth_login_success", f"account:{official.account_id}"),
        ("AUTH_PRIVILEGED_LOGIN_SUCCESS", f"account:{official.account_id}"),
    ]


@pytest.mark.parametrize("role", ["polling_official", "auditor"])
def test_the_password_alone_opens_no_admin_route(
    client: TestClient, db_session: Session, make_staff, role: str
) -> None:
    """SR-06 test 2: after the password step the session is only pending, and every admin route says 401."""
    staff = make_staff(role)

    assert login(client, staff).status_code == 204

    assert session_row(db_session, client.cookies[SESSION_COOKIE]).stage == SessionStage.MFA_PENDING
    for method, path in ADMIN_ROUTES:
        response = client.request(method, path)
        assert (response.status_code, response.json()) == (401, {"detail": "not_signed_in"}), path


def test_bad_codes_count_toward_the_lock(client: TestClient, db_session: Session, make_staff, clock) -> None:
    """SR-06 test 3: a wrong, reused or two-steps-away code is a failed attempt; five lock out even the right details."""
    staff = make_staff("auditor")
    used = code_at(staff, clock)
    login(client, staff)
    assert verify(client, used).status_code == 200
    client.post("/api/auth/logout")

    login(client, staff)
    for count, code in enumerate((wrong_code(staff, clock), used, code_at(staff, clock, 2)), start=1):
        assert outcome(verify(client, code)) == SIGN_IN_FAILED
        assert account_row(db_session, staff).failed_logins == count
    for count in (4, 5):
        assert outcome(login(client, staff, WRONG_PASSWORD)) == SIGN_IN_FAILED
        assert account_row(db_session, staff).failed_logins == count
    assert account_row(db_session, staff).locked_until > clock.now

    clock.advance(seconds=30)  # a fresh, valid code
    assert outcome(login(client, staff)) == SIGN_IN_FAILED
    assert outcome(verify(client, code_at(staff, clock))) == SIGN_IN_FAILED


def test_staff_session_lasts_ten_minutes_and_cannot_be_extended(
    client: TestClient, db_session: Session, make_staff, sign_in, clock
) -> None:
    """SR-06 test 4: accepted at 9:59, refused at 10:01, and an extension is refused with 409."""
    sign_in(make_staff("auditor"))
    issued, token = clock.now, client.cookies[SESSION_COOKIE]

    assert outcome(client.post(EXTEND)) == LIMIT
    stored = session_row(db_session, token)
    assert (stored.extensions, stored.expires_at) == (2, issued + timedelta(minutes=10))
    clock.now = issued + timedelta(minutes=9, seconds=59)
    assert client.get("/api/admin/audit-log/verify").status_code == 200
    clock.now = issued + timedelta(minutes=10, seconds=1)
    assert client.get("/api/admin/audit-log/verify").status_code == 401


def test_elector_sign_in_is_unchanged(client: TestClient, db_session: Session, make_voter, sign_in) -> None:
    """SR-06 test 5: electors get the same answer as before, two extensions, and no privileged audit entry."""
    before = last_id(db_session)
    voter = make_voter()

    verified = sign_in(voter)

    assert (verified.status_code, verified.json()) == (200, {"display_name": voter.full_name})
    assert session_row(db_session, client.cookies[SESSION_COOKIE]).extensions == 0
    assert [client.post(EXTEND).status_code for _ in range(2)] == [204, 204]
    assert outcome(client.post(EXTEND)) == LIMIT
    assert events(db_session, before, "AUTH_PRIVILEGED_LOGIN_SUCCESS") == []
    assert len(events(db_session, before, "auth_login_success")) == 1


@pytest.mark.parametrize("role", ["polling_official", "auditor"])
def test_staff_account_cannot_exist_without_a_code_secret(db_session: Session, make_staff, role: str) -> None:
    """SR-06 test 6: the database refuses an account with no TOTP secret, and the script always makes one."""
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.execute(
            text(
                "INSERT INTO accounts (username, password_hash, role, totp_secret_enc) "
                "VALUES (:username, 'x', :role, NULL)"
            ),
            {"username": f"no.secret.{role}", "role": role},
        )

    staff = make_staff(role)
    assert decrypt(account_row(db_session, staff).totp_secret_enc, "accounts.totp_secret") == staff.totp_secret


def test_staff_sign_in_audit_holds_no_codes_or_secrets(
    client: TestClient, db_session: Session, make_staff, clock, audit_text
) -> None:
    """SR-06 test 7: failures and the privileged success are audited by account and event only.
    SR-16: STAFF_CREATED now names the new account (it was "system"), and every column is searched."""
    before = last_id(db_session)
    staff = make_staff("polling_official")
    bad, good = wrong_code(staff, clock), code_at(staff, clock)

    login(client, staff, WRONG_PASSWORD)
    login(client, staff)
    verify(client, bad)
    verify(client, good)

    rows = events(db_session, before)
    assert {"auth_password_failed", "auth_totp_failed", "auth_login_success", "AUTH_PRIVILEGED_LOGIN_SUCCESS"} <= {
        r.event_type for r in rows
    }
    assert {r.actor for r in rows} == {f"account:{staff.account_id}"}
    assert {r.role for r in rows} == {"polling_official"}
    assert {r.category for r in rows if r.event_type == "AUTH_PRIVILEGED_LOGIN_SUCCESS"} == {"privileged_access"}
    recorded = audit_text(before)
    secrets = [staff.password, WRONG_PASSWORD, staff.totp_secret, bad, good, client.cookies[SESSION_COOKIE]]
    assert [s for s in secrets if s in recorded] == []
