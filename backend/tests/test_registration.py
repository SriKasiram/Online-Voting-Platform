"""Registration: verify the roll entry, choose an account, confirm the authenticator app."""

import json
import logging
import re
import threading
from collections.abc import Callable
from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app import config
from app.deps import get_db
from app.main import app
from app.models import Account, AccountRole, AuditLogEntry, Division, ElectoralRollEntry, RegistrationSession
from app.security import (
    decrypt,
    encrypt,
    enrolment_code_hash,
    rate_limiter,
    roll_lookup,
    utc_now,
)

VERIFY = "/api/register/verify"
ACCOUNT = "/api/register/account"
CONFIRM = "/api/register/confirm"
GENERIC_FAILURE = b'{"detail":"registration_failed"}'
PASSWORD = "a long enough password"


def wrong_code(secret: str) -> str:
    totp = pyotp.TOTP(secret)
    valid = {totp.at(utc_now() + timedelta(seconds=s)) for s in (-30, 0, 30)}
    return next(code for code in ("000000", "111111", "222222", "333333") if code not in valid)


def choose_account(client: TestClient, username: str = "new.voter", password: str = PASSWORD):
    return client.post(ACCOUNT, json={"username": username, "password": password})


def register(client: TestClient, person, username: str = "new.voter") -> str:
    """Runs all three steps and returns the authenticator secret."""
    assert client.post(VERIFY, json=person.verify_body()).status_code == 204
    secret = choose_account(client, username).json()["secret"]
    assert client.post(CONFIRM, json={"otp_code": pyotp.TOTP(secret).now()}).status_code == 204
    return secret


def roll_entry(db_session: Session, person) -> ElectoralRollEntry:
    db_session.expire_all()
    return db_session.get_one(ElectoralRollEntry, person.roll_id)


# ---------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------


def test_full_registration_then_a_normal_sign_in(client: TestClient, db_session: Session, make_person) -> None:
    person = make_person()

    started = client.post(VERIFY, json=person.verify_body())
    assert started.status_code == 204
    assert "registration_session" in started.cookies

    chosen = choose_account(client, "New.Voter")
    assert chosen.status_code == 200
    assert chosen.headers["cache-control"] == "no-store"
    secret = chosen.json()["secret"]
    assert re.fullmatch(r"[A-Z2-7]{32}", secret)
    uri = chosen.json()["otpauth_uri"]
    assert uri.startswith("otpauth://totp/") and "issuer=Australian%20E-Voting%20Platform" in uri
    assert "New.Voter" in uri

    confirmed = client.post(CONFIRM, json={"otp_code": pyotp.TOTP(secret).now()})
    assert confirmed.status_code == 204
    assert confirmed.content == b""

    account = db_session.scalars(select(Account).where(Account.username == "new.voter")).one()
    assert account.role == AccountRole.VOTER
    assert account.roll_id == person.roll_id
    assert account.password_hash.startswith("$argon2id$")
    assert decrypt(account.totp_secret_enc, "accounts.totp_secret") == secret
    entry = roll_entry(db_session, person)
    assert entry.registered_at is not None
    assert entry.enrolment_code_hash is None
    assert db_session.scalar(select(func.count()).select_from(RegistrationSession)) == 0

    # Registration does not sign the voter in. They sign in normally.
    assert client.get("/api/ballot").status_code == 401
    client.post("/api/auth/login", json={"username": "new.voter", "password": PASSWORD})
    signed_in = client.post("/api/auth/verify", json={"otp_code": pyotp.TOTP(secret).now()})
    assert signed_in.status_code == 200
    assert signed_in.json() == {"display_name": f"{person.given_name} {person.surname}"}


def test_details_are_normalised_before_matching(client: TestClient, make_person) -> None:
    person = make_person()
    body = person.verify_body(
        given_name=f"  {person.given_name.upper()} ",
        surname=f" {person.surname.lower()}  ",
        postcode=" 30 00 ",
        enrolment_code=person.enrolment_code.lower().replace("-", " "),
    )

    assert client.post(VERIFY, json=body).status_code == 204


# ---------------------------------------------------------------
# Step 1 never reveals why it failed
# ---------------------------------------------------------------

DETAIL_CASES = {
    "wrong given name": {"given_name": "Alexis"},
    "wrong surname": {"surname": "Somebody"},
    "wrong date of birth": {"date_of_birth": "1985-06-16"},
    "date that is not a date": {"date_of_birth": "15/06/1985"},
    "wrong postcode": {"postcode": "3001"},
    "wrong enrolment code": {"enrolment_code": "TEST-CODE-9999"},
}
ENTRY_CASES = {
    "not enrolled": {"enrolled": False},
    "already registered": {"registered": True},
    "expired code": {"code_expires_in": timedelta(seconds=-1)},
    "code locked after too many wrong tries": {"code_attempts": config.ENROLMENT_CODE_MAX_ATTEMPTS},
}


@pytest.mark.parametrize("case", [*DETAIL_CASES, *ENTRY_CASES])
def test_every_step_1_failure_gets_the_identical_response(client: TestClient, make_person, case: str) -> None:
    person = make_person(**ENTRY_CASES.get(case, {}))

    response = client.post(VERIFY, json=person.verify_body(**DETAIL_CASES.get(case, {})))

    assert response.status_code == 400
    assert response.content == GENERIC_FAILURE
    assert "registration_session" not in response.cookies


def test_enrolment_code_works_only_once(client: TestClient, make_person) -> None:
    person = make_person()
    assert client.post(VERIFY, json=person.verify_body()).status_code == 204

    again = TestClient(app).post(VERIFY, json=person.verify_body())

    assert again.status_code == 400
    assert again.content == GENERIC_FAILURE


def test_wrong_codes_lock_the_entry(client: TestClient, db_session: Session, make_person) -> None:
    person = make_person()
    for _ in range(config.ENROLMENT_CODE_MAX_ATTEMPTS):
        assert client.post(VERIFY, json=person.verify_body(enrolment_code="WRONG-CODE")).status_code == 400

    # The right code no longer works either
    response = client.post(VERIFY, json=person.verify_body())

    assert response.content == GENERIC_FAILURE
    assert roll_entry(db_session, person).code_attempts == config.ENROLMENT_CODE_MAX_ATTEMPTS


def test_rate_limit_per_client_ip(
    client: TestClient, db_session: Session, make_person, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "REGISTER_VERIFY_LIMIT_PER_IP", 3)
    person = make_person()
    stranger = person.verify_body(surname="Nobody")
    for _ in range(3):
        client.post(VERIFY, json=stranger)

    blocked = client.post(VERIFY, json=person.verify_body(enrolment_code="WRONG-CODE"))
    assert blocked.content == GENERIC_FAILURE
    # A blocked request does not count toward locking the entry
    assert roll_entry(db_session, person).code_attempts == 0
    assert client.post(VERIFY, json=person.verify_body()).content == GENERIC_FAILURE

    rate_limiter.clear()
    assert client.post(VERIFY, json=person.verify_body()).status_code == 204


def test_rate_limit_per_roll_entry(
    client: TestClient, db_session: Session, make_person, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "REGISTER_VERIFY_LIMIT_PER_ENTRY", 2)
    person = make_person()
    for _ in range(2):
        client.post(VERIFY, json=person.verify_body(enrolment_code="WRONG-CODE"))

    response = client.post(VERIFY, json=person.verify_body())

    assert response.content == GENERIC_FAILURE
    assert roll_entry(db_session, person).code_attempts == 2


# ---------------------------------------------------------------
# The registration session
# ---------------------------------------------------------------


def test_registration_session_expires(client: TestClient, db_session: Session, make_person) -> None:
    person = make_person()
    client.post(VERIFY, json=person.verify_body())
    registration = db_session.scalars(select(RegistrationSession)).one()
    registration.expires_at = utc_now() - timedelta(seconds=1)
    db_session.commit()

    response = choose_account(client)

    assert response.status_code == 401
    assert response.json() == {"detail": "registration_session_invalid"}
    # Expired sessions are deleted as requests arrive
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(RegistrationSession)) == 0


def test_steps_cannot_be_skipped(client: TestClient, make_person) -> None:
    assert choose_account(client).status_code == 401
    assert client.post(CONFIRM, json={"otp_code": "123456"}).status_code == 401

    client.post(VERIFY, json=make_person().verify_body())

    # Step 3 needs step 2 first
    assert client.post(CONFIRM, json={"otp_code": "123456"}).status_code == 401


def test_steps_cannot_be_replayed(client: TestClient, make_person) -> None:
    person = make_person()
    client.post(VERIFY, json=person.verify_body())
    secret = choose_account(client).json()["secret"]

    assert choose_account(client, "other.name").status_code == 401

    assert client.post(CONFIRM, json={"otp_code": pyotp.TOTP(secret).now()}).status_code == 204
    assert client.post(CONFIRM, json={"otp_code": pyotp.TOTP(secret).now()}).status_code == 401
    assert client.post(VERIFY, json=person.verify_body()).content == GENERIC_FAILURE


def test_wrong_authenticator_codes_end_the_registration(client: TestClient, db_session: Session, make_person) -> None:
    client.post(VERIFY, json=make_person().verify_body())
    secret = choose_account(client).json()["secret"]

    for _ in range(config.REGISTRATION_CODE_MAX_ATTEMPTS - 1):
        response = client.post(CONFIRM, json={"otp_code": wrong_code(secret)})
        assert response.json() == {"detail": "wrong_code"}
    # The registration is kept for another try until the attempts run out
    assert db_session.scalar(select(func.count()).select_from(RegistrationSession)) == 1

    last = client.post(CONFIRM, json={"otp_code": wrong_code(secret)})

    assert last.json() == {"detail": "too_many_attempts"}
    assert client.post(CONFIRM, json={"otp_code": pyotp.TOTP(secret).now()}).status_code == 401
    assert db_session.scalar(select(func.count()).select_from(Account)) == 0


# ---------------------------------------------------------------
# Usernames and passwords
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("username", "password", "reason"),
    [
        ("new.voter", "x" * 11, "password_too_short"),
        ("Same.Name_1234", "same.name_1234", "password_is_username"),
        ("ab", PASSWORD, "username_invalid"),
        ("a" * 33, PASSWORD, "username_invalid"),
        ("has space", PASSWORD, "username_invalid"),
        ("no-hyphens", PASSWORD, "username_invalid"),
    ],
)
def test_account_rules(client: TestClient, make_person, username: str, password: str, reason: str) -> None:
    client.post(VERIFY, json=make_person().verify_body())

    response = choose_account(client, username, password)

    assert response.status_code == 400
    assert response.json() == {"detail": reason}
    # Exactly 12 characters, with no other rules, is fine
    assert choose_account(client, "ok.name", "twelve chars").status_code == 200


def test_usernames_are_unique_ignoring_case(client: TestClient, make_person, make_voter) -> None:
    existing = make_voter()
    client.post(VERIFY, json=make_person().verify_body())

    response = choose_account(client, existing.username.upper())

    assert response.status_code == 409
    assert response.json() == {"detail": "username_taken"}


def test_username_held_by_a_registration_in_progress_is_taken(client: TestClient, make_person) -> None:
    # Two browsers, both using the test's database through the client fixture
    first, second = client, TestClient(app)
    first.post(VERIFY, json=make_person().verify_body())
    assert choose_account(first, "pending.name").status_code == 200
    second.post(VERIFY, json=make_person().verify_body())

    assert choose_account(second, "Pending.Name").status_code == 409


# ---------------------------------------------------------------
# Secrets and the audit log
# ---------------------------------------------------------------


def test_totp_secret_is_kept_out_of_accounts_logs_and_later_responses(
    client: TestClient, db_session: Session, make_person, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    person = make_person()
    client.post(VERIFY, json=person.verify_body())
    secret = choose_account(client).json()["secret"]

    # Before confirm: no account, and the session holds the secret only encrypted
    assert db_session.scalar(select(func.count()).select_from(Account)) == 0
    pending = db_session.scalars(select(RegistrationSession)).one()
    assert pending.totp_secret_enc is not None and secret.encode() not in pending.totp_secret_enc

    later = [client.post(CONFIRM, json={"otp_code": pyotp.TOTP(secret).now()})]
    later.append(client.post("/api/auth/login", json={"username": "new.voter", "password": PASSWORD}))
    later.append(client.post("/api/auth/verify", json={"otp_code": pyotp.TOTP(secret).now()}))

    assert all(secret not in response.text for response in later)
    assert secret not in caplog.text
    audit_text = json.dumps([[e.actor, e.details] for e in db_session.scalars(select(AuditLogEntry))])
    assert secret not in audit_text


def test_audit_log_holds_no_personal_data(client: TestClient, db_session: Session, make_person) -> None:
    before = db_session.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))
    person = make_person()
    client.post(VERIFY, json=person.verify_body(enrolment_code="WRONG-CODE"))
    secret = register(client, person, username="private.name")

    entries = db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.id > before).order_by(AuditLogEntry.id)).all()

    assert [e.event_type for e in entries] == ["REGISTRATION_FAILED", "REGISTRATION_STARTED", "REGISTRATION_COMPLETED"]
    # The only identifiers: the client IP before a match, the roll entry id after it
    assert entries[0].actor == "testclient"
    assert all(e.actor == f"roll:{person.roll_id}" for e in entries[1:])
    text = json.dumps([e.details for e in entries]).casefold()
    for private in (
        person.given_name,
        person.surname,
        person.date_of_birth,
        person.postcode,
        person.enrolment_code,
        "WRONG-CODE",
        "private.name",
        PASSWORD,
        secret,
    ):
        assert private.casefold() not in text


# ---------------------------------------------------------------
# Two registrations at once
# ---------------------------------------------------------------


def run_together(*calls: Callable[[], object]) -> list:
    """Starts every call at the same moment, each on its own thread."""
    barrier = threading.Barrier(len(calls))
    results: list = [None] * len(calls)

    def worker(index: int, call: Callable[[], object]) -> None:
        barrier.wait()
        results[index] = call()

    threads = [threading.Thread(target=worker, args=(i, call)) for i, call in enumerate(calls)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def test_two_simultaneous_registrations_create_one_account(engine) -> None:
    """Needs real, separate transactions, so this test commits its own data and removes it afterwards."""

    def real_db():
        with Session(engine) as session:
            yield session

    code = "RACE-CODE-0001"
    details = {"given_name": "Race", "surname": "Tester", "date_of_birth": "1970-01-01", "postcode": "3999"}
    body = details | {"enrolment_code": code}
    with Session(engine) as setup:
        before = setup.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))
        division = Division(name="Racetown", state="Victoria")
        setup.add(division)
        setup.flush()
        entry = ElectoralRollEntry(
            roll_lookup=roll_lookup(**details),
            full_name_enc=encrypt("Race Tester", "electoral_roll.full_name"),
            address_enc=encrypt("1 Race Street", "electoral_roll.address"),
            division_id=division.id,
            enrolled=True,
            enrolment_code_hash=enrolment_code_hash(code),
            code_expires_at=utc_now() + timedelta(days=1),
        )
        setup.add(entry)
        setup.commit()
        roll_id = entry.id

    app.dependency_overrides[get_db] = real_db
    try:
        first, second = TestClient(app), TestClient(app)

        # Both send step 1 at the same moment: the code can be spent only once
        results = run_together(lambda: first.post(VERIFY, json=body), lambda: second.post(VERIFY, json=body))
        assert sorted(r.status_code for r in results) == [204, 400]

        # Push the race to the last step: give the losing client a fresh code too
        loser = second if results[1].status_code == 400 else first
        with Session(engine) as session:
            again = session.get_one(ElectoralRollEntry, roll_id)
            again.enrolment_code_hash = enrolment_code_hash(code)
            again.code_expires_at = utc_now() + timedelta(days=1)
            session.commit()
        assert loser.post(VERIFY, json=body).status_code == 204
        totp_secrets = [
            choose_account(c, name).json()["secret"] for c, name in ((first, "racer.one"), (second, "racer.two"))
        ]

        results = run_together(
            lambda: first.post(CONFIRM, json={"otp_code": pyotp.TOTP(totp_secrets[0]).now()}),
            lambda: second.post(CONFIRM, json={"otp_code": pyotp.TOTP(totp_secrets[1]).now()}),
        )

        assert sorted(r.status_code for r in results) == [204, 409]
        with Session(engine) as session:
            accounts = session.scalar(select(func.count()).select_from(Account).where(Account.roll_id == roll_id))
            assert accounts == 1
    finally:
        app.dependency_overrides.clear()
        with Session(engine) as cleanup:
            for statement in (
                delete(Account).where(Account.roll_id == roll_id),
                delete(RegistrationSession).where(RegistrationSession.roll_id == roll_id),
                delete(ElectoralRollEntry).where(ElectoralRollEntry.id == roll_id),
                delete(Division).where(Division.name == "Racetown"),
                delete(AuditLogEntry).where(AuditLogEntry.id > before),
            ):
                cleanup.execute(statement)
            cleanup.commit()
