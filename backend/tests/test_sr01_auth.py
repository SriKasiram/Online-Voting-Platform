"""
SR-01: every voter signs in with a password checked against an Argon2id hash and
a code from an authenticator app (TOTP) before any voting route opens. Failed
attempts lock the account, and each client IP has a limit on sign-in requests.
"""

import threading
from collections.abc import Iterator
from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, delete, func, select, text
from sqlalchemy.orm import Session

from helpers import account_row
from app import security
from app.config import Settings, settings
from app.deps import get_db
from app.main import app
from app.models import Account, AccountRole, AuditLogEntry, AuthSession, SessionStage
from app.security import SESSION_COOKIE, encrypt, hash_password, hash_token, new_totp_secret

LOGIN = "/api/auth/login"
VERIFY = "/api/auth/verify"
GENERIC = {"detail": "invalid_credentials"}
WRONG_PASSWORD = "not the password"
# Every route that needs a signed-in voter, with a body of the right shape
VOTING_ROUTES = [
    ("GET", "/api/ballot", None),
    ("POST", "/api/ballot/submit", {"ballot_token": "any", "ranked_candidate_ids": [1]}),
    ("POST", "/api/auth/extend", None),
]
EVENTS = {"auth_password_failed", "auth_totp_failed", "auth_account_locked", "auth_rate_limited", "auth_login_success"}

# SR-02: the `clock` fixture moved to conftest.py so the SR-02 tests share it. Behaviour unchanged.


def code(voter, clock, steps: int = 0) -> str:
    """The voter's authenticator code, `steps` 30-second steps away from the clock's time."""
    return pyotp.TOTP(voter.totp_secret).at(clock.now + timedelta(seconds=30 * steps))


def wrong_code(voter, clock) -> str:
    valid = {code(voter, clock, steps) for steps in (-1, 0, 1)}
    return next(c for c in ("000000", "111111", "222222", "333333") if c not in valid)


def login(client: TestClient, voter, password: str | None = None):
    return client.post(LOGIN, json={"username": voter.username, "password": password or voter.password})


def verify(client: TestClient, otp: str, **kwargs):
    return client.post(VERIFY, json={"otp_code": otp}, **kwargs)


def test_password_alone_opens_no_voting_route(client: TestClient, make_voter) -> None:
    """SR-01 test 1: the right password without the code leaves /api/ballot at 401."""
    voter = make_voter()

    assert login(client, voter).status_code == 204
    assert client.get("/api/ballot").status_code == 401


def test_pending_session_is_refused_by_every_voting_route(client: TestClient, make_voter) -> None:
    """SR-01 test 2: a session waiting for its code opens no voting route."""
    login(client, make_voter())

    for method, path, body in VOTING_ROUTES:
        assert client.request(method, path, json=body).status_code == 401, path


def test_password_and_code_open_voting_under_a_new_token(
    client: TestClient, db_session: Session, make_voter, clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-01 test 3: both steps open voting under a new token, in a cookie with the required flags."""
    monkeypatch.setattr(settings, "cookie_secure", True)
    voter = make_voter()
    login(client, voter)
    pending = client.cookies[SESSION_COOKIE]

    response = verify(client, code(voter, clock))

    signed_in = client.cookies[SESSION_COOKIE]
    assert response.status_code == 200
    assert signed_in != pending
    assert client.get("/api/ballot").status_code == 200
    assert db_session.get_one(AuthSession, hash_token(signed_in)).stage == SessionStage.AUTHENTICATED
    assert db_session.get(AuthSession, hash_token(pending)) is None
    cookie = response.headers["set-cookie"].lower()
    assert all(flag in cookie for flag in ("httponly", "samesite=strict", "secure", "path=/"))
    assert "max-age" not in cookie and "expires" not in cookie


def test_wrong_password_and_unknown_username_get_the_same_answer(client: TestClient, make_voter) -> None:
    """SR-01 test 4: identical status and body, so the answer never shows whether a username exists."""
    wrong_password = login(client, make_voter(), WRONG_PASSWORD)
    unknown_user = client.post(LOGIN, json={"username": "nobody.here", "password": WRONG_PASSWORD})

    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json() == GENERIC
    assert "set-cookie" not in wrong_password.headers and "set-cookie" not in unknown_user.headers


def test_mixed_failures_lock_the_account_until_lock_minutes_pass(
    client: TestClient, db_session: Session, make_voter, clock
) -> None:
    """SR-01 test 5: password and code failures count together, and while locked even the right details fail."""
    voter = make_voter()
    for _ in range(settings.max_failed_attempts - 2):
        assert login(client, voter, WRONG_PASSWORD).status_code == 401
    # The right password does not reset the count: only a full sign in does
    assert login(client, voter).status_code == 204
    for _ in range(2):
        assert verify(client, wrong_code(voter, clock)).status_code == 401

    account = account_row(db_session, voter)
    assert account.failed_logins == settings.max_failed_attempts
    assert account.locked_until == clock.now + timedelta(minutes=settings.lock_minutes)

    sixth = login(client, voter)
    assert (sixth.status_code, sixth.json()) == (401, GENERIC)

    clock.advance(minutes=settings.lock_minutes, seconds=1)
    assert login(client, voter).status_code == 204
    assert verify(client, code(voter, clock)).status_code == 200


def test_a_full_sign_in_resets_the_count(client: TestClient, db_session: Session, make_voter, clock) -> None:
    """SR-01 test 6: failures before a successful sign in no longer count toward the lock."""
    voter = make_voter()
    for _ in range(settings.max_failed_attempts - 1):
        login(client, voter, WRONG_PASSWORD)
    assert account_row(db_session, voter).failed_logins == settings.max_failed_attempts - 1

    login(client, voter)
    assert verify(client, code(voter, clock)).status_code == 200

    account = account_row(db_session, voter)
    assert (account.failed_logins, account.locked_until) == (0, None)
    login(client, voter, WRONG_PASSWORD)
    assert account_row(db_session, voter).locked_until is None


def test_a_code_cannot_be_used_twice(client: TestClient, db_session: Session, make_voter, clock) -> None:
    """SR-01 test 7: a code is refused the second time within its 30 seconds, and that counts as a failure."""
    voter = make_voter()
    used = code(voter, clock)
    login(client, voter)
    assert verify(client, used).status_code == 200
    client.post("/api/auth/logout")

    login(client, voter)
    replay = verify(client, used)

    assert (replay.status_code, replay.json()) == (401, GENERIC)
    assert account_row(db_session, voter).failed_logins == 1


@pytest.mark.parametrize(("steps", "status_code"), [(-2, 401), (-1, 200), (1, 200), (2, 401)])
def test_codes_one_step_either_side_are_accepted(
    client: TestClient, make_voter, clock, steps: int, status_code: int
) -> None:
    """SR-01 test 8: codes from steps -1 and +1 are accepted for clock drift, -2 and +2 are not."""
    voter = make_voter()
    login(client, voter)

    assert verify(client, code(voter, clock, steps)).status_code == status_code


def test_expired_or_spent_pending_session_is_refused(client: TestClient, make_voter, clock) -> None:
    """SR-01 test 9: a pending session ends after MFA_PENDING_MINUTES and cannot be used again after success."""
    voter = make_voter()
    login(client, voter)
    clock.advance(minutes=settings.mfa_pending_minutes, seconds=1)
    assert verify(client, code(voter, clock)).status_code == 401

    login(client, voter)
    pending = client.cookies[SESSION_COOKIE]
    assert verify(client, code(voter, clock)).status_code == 200

    replay = TestClient(app, base_url="https://testserver")
    headers = {"cookie": f"{SESSION_COOKIE}={pending}"}
    assert verify(replay, code(voter, clock, 1), headers=headers).status_code == 401
    assert replay.get("/api/ballot", headers=headers).status_code == 401


def test_parallel_wrong_passwords_are_all_counted(engine: Engine) -> None:
    """
    SR-01 test 10: MAX_FAILED_ATTEMPTS wrong passwords sent at the same moment
    are all counted and lock the account. Needs real, separate transactions, so
    this test commits its own account and removes it afterwards.
    """

    def real_db() -> Iterator[Session]:
        with Session(engine) as session:
            yield session

    with Session(engine) as setup:
        account = Account(
            username="parallel.voter",
            password_hash=hash_password("the right password"),
            role=AccountRole.AUDITOR,  # SR-05: an account with no roll entry must be staff now
            totp_secret_enc=encrypt(new_totp_secret(), "accounts.totp_secret"),
        )
        setup.add(account)
        setup.commit()
        account_id = account.id

    attempts = settings.max_failed_attempts
    barrier = threading.Barrier(attempts)
    statuses: list[int] = []

    def attempt() -> None:
        api = TestClient(app, base_url="https://testserver")
        barrier.wait()
        statuses.append(api.post(LOGIN, json={"username": "parallel.voter", "password": WRONG_PASSWORD}).status_code)

    app.dependency_overrides[get_db] = real_db
    try:
        threads = [threading.Thread(target=attempt) for _ in range(attempts)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        with Session(engine) as check:
            stored = check.get_one(Account, account_id)
            assert statuses == [401] * attempts
            assert stored.failed_logins == attempts
            assert stored.locked_until is not None
    finally:
        app.dependency_overrides.clear()
        with Session(engine) as cleanup:
            # SR-16: audit rows cannot be deleted (append-only trigger); TRUNCATE fires no row trigger.
            # Only this test's committed rows are there: every other test rolls back.
            cleanup.execute(text("TRUNCATE audit_log"))
            cleanup.execute(delete(AuthSession).where(AuthSession.account_id == account_id))
            cleanup.execute(delete(Account).where(Account.id == account_id))
            cleanup.commit()


def test_ip_limit_returns_429_and_follows_the_settings(
    client: TestClient, make_voter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-01 test 11: after RATE_LIMIT_ATTEMPTS requests in RATE_LIMIT_WINDOW_SECONDS, one IP gets 429."""
    monkeypatch.setattr(settings, "rate_limit_attempts", 3)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 60)
    seconds = [1000.0]
    monkeypatch.setattr(security, "monotonic", lambda: seconds[0])
    voter = make_voter()

    for _ in range(3):
        assert login(client, voter, WRONG_PASSWORD).status_code == 401
    blocked = [
        login(client, voter),
        verify(client, "123456"),
        # A forwarded-for header cannot pose as another address
        client.post(
            LOGIN,
            json={"username": voter.username, "password": voter.password},
            headers={"X-Forwarded-For": "203.0.113.9"},
        ),
    ]

    assert all((r.status_code, r.json()) == (429, {"detail": "too_many_requests"}) for r in blocked)
    other_ip = TestClient(app, base_url="https://testserver", client=("198.51.100.7", 50000))
    assert login(other_ip, voter).status_code == 204
    seconds[0] += 61
    assert login(client, voter).status_code == 204


def test_stored_passwords_are_argon2id(db_session: Session, make_voter) -> None:
    """SR-01 test 12: every stored password hash is Argon2id."""
    make_voter()

    hashes = db_session.scalars(select(Account.password_hash)).all()

    assert hashes and all(h.startswith("$argon2id$") for h in hashes)


def test_locked_and_unknown_users_still_run_the_dummy_hash(
    client: TestClient, db_session: Session, make_voter, clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-01 test 13: an unknown username and a locked account both run Argon2id against the dummy hash."""
    voter = make_voter()
    real = security._hasher
    checked: list[str] = []

    class Spy:
        def verify(self, password_hash: str, password: str) -> bool:
            checked.append(password_hash)
            return real.verify(password_hash, password)

    monkeypatch.setattr(security, "_hasher", Spy())

    client.post(LOGIN, json={"username": "nobody.here", "password": WRONG_PASSWORD})
    account = account_row(db_session, voter)
    account.locked_until = clock.now + timedelta(minutes=1)
    db_session.commit()
    login(client, voter)

    assert checked == [security._DUMMY_HASH, security._DUMMY_HASH]


def test_audit_records_each_event_without_secrets(
    client: TestClient, db_session: Session, make_voter, clock, monkeypatch: pytest.MonkeyPatch, audit_text
) -> None:
    """SR-01 test 14: every sign-in event is audited with only the account (or "unknown") and the event type.
    SR-16: and the allow-listed outcome and role, with no free text; every column is searched for secrets."""
    before = db_session.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))
    voter = make_voter()
    secrets = [voter.password, WRONG_PASSWORD, voter.username, voter.totp_secret]

    login(client, voter, WRONG_PASSWORD)
    client.post(LOGIN, json={"username": "nobody.here", "password": WRONG_PASSWORD})
    login(client, voter)
    secrets += [client.cookies[SESSION_COOKIE], wrong_code(voter, clock), code(voter, clock)]
    verify(client, wrong_code(voter, clock))
    verify(client, code(voter, clock))
    secrets.append(client.cookies[SESSION_COOKIE])
    for _ in range(settings.max_failed_attempts):
        login(client, voter, WRONG_PASSWORD)
    monkeypatch.setattr(settings, "rate_limit_attempts", 0)
    login(client, voter)

    rows = db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.id > before)).all()
    assert {r.event_type for r in rows} == EVENTS
    assert {r.actor for r in rows} == {f"account:{voter.account_id}", "unknown"}
    assert all(r.details is None and r.reason is None for r in rows)
    assert {r.role for r in rows} == {"elector", "unknown"}
    recorded = audit_text(before)
    assert [s for s in secrets if s in recorded] == []


def test_settings_defaults() -> None:
    """SR-01: the defaults used when the environment sets nothing. SR-04: the pending default is now 2 minutes."""
    defaults = {name: field.default for name, field in Settings.model_fields.items()}

    assert {k: defaults[k] for k in ("max_failed_attempts", "lock_minutes", "mfa_pending_minutes")} == {
        "max_failed_attempts": 5,
        "lock_minutes": 15,
        "mfa_pending_minutes": 2,
    }
    assert (defaults["rate_limit_attempts"], defaults["rate_limit_window_seconds"]) == (20, 300)
    assert defaults["cookie_secure"] is True
