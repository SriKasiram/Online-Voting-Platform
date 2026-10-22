"""
Shared test setup.

Each run rebuilds a separate database (POSTGRES_TEST_DB, default evoting_test)
from the Alembic migrations, so every run also proves the migrations work.
Tests make their own election, roll entries and voters with the factories
below and never rely on the seed script. Each test runs inside one
transaction that is rolled back at the end, so nothing leaks between tests.
"""

import itertools
import re
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

import pyotp
import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import Connection, Engine, create_engine, select, text
from sqlalchemy.orm import Session

from app import ballot_definitions, deps, security
from app.config import BACKEND_DIR, settings
from app.deps import get_db
from app.main import app
from app.models import Account, AccountRole, Candidate, Division, Election, ElectionStatus, ElectoralRollEntry
from app.routers import auth, ballot
from app.security import (
    encrypt,
    enrolment_code_hash,
    hash_password,
    new_totp_secret,
    rate_limiter,
    roll_lookup,
    utc_now,
)
from scripts import ballot_definition as ballot_definition_script
from scripts.ballot_definition import build_payload, ensure_delegate_keys, sign, store_active
from scripts.create_staff import create_staff
from scripts.sign_roll import sign_record

# SR-02: a fixed polling date, so no test depends on today's date
POLLING_DATE = date(2027, 5, 15)
# SR-07: the fixture definition's validity, wide enough for every clock the tests use
DEFINITION_VALID_FROM = datetime(2000, 1, 1, tzinfo=UTC)
DEFINITION_VALID_UNTIL = datetime(2100, 1, 1, tzinfo=UTC)

CANDIDATE_NAMES = [
    ("Hana", "Ortega", "Harbour Party"),
    ("Daniel", "Whitfield", "Rural Alliance"),
    ("Mei-Lin", "Tran", "Green Horizon"),
]


def recreate_test_database(name: str) -> None:
    # Refuse to drop anything that is not clearly a throwaway test database
    if not re.fullmatch(r"[a-z][a-z0-9_]*_test", name) or name == settings.postgres_db:
        raise RuntimeError(
            f"POSTGRES_TEST_DB must end in _test and differ from POSTGRES_DB (got {name!r})"
        )
    admin = create_engine(settings.database_url("postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
            connection.execute(text(f'CREATE DATABASE "{name}"'))
    finally:
        admin.dispose()


@pytest.fixture(scope="session")
def alembic_config() -> Config:
    return Config(str(BACKEND_DIR / "alembic.ini"))


@pytest.fixture(scope="session")
def engine(alembic_config: Config) -> Iterator[Engine]:
    name = settings.postgres_test_db
    recreate_test_database(name)
    test_engine = create_engine(settings.database_url(name))
    with test_engine.begin() as connection:
        alembic_config.attributes["connection"] = connection
        command.upgrade(alembic_config, "head")
    yield test_engine
    test_engine.dispose()


@pytest.fixture
def connection(engine: Engine) -> Iterator[Connection]:
    """One connection per test, inside a transaction that is rolled back afterwards."""
    with engine.connect() as test_connection:
        transaction = test_connection.begin()
        try:
            yield test_connection
        finally:
            transaction.rollback()


def nested_session(connection: Connection) -> Session:
    # commit() inside the app or a test only releases a savepoint, so the
    # outer transaction can still undo everything
    return Session(bind=connection, join_transaction_mode="create_savepoint")


@pytest.fixture
def db_session(connection: Connection) -> Iterator[Session]:
    """A session for arranging and reading data in a test. Sees what the API wrote."""
    with nested_session(connection) as session:
        yield session


@pytest.fixture
def client(connection: Connection) -> Iterator[TestClient]:
    """An API client whose requests use the test's transaction. Keeps cookies between requests."""

    def test_db() -> Iterator[Session]:
        with nested_session(connection) as session:
            yield session

    app.dependency_overrides[get_db] = test_db
    # SR-01: https, so a Secure session cookie comes back the way a browser would send it
    with TestClient(app, base_url="https://testserver") as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def fresh_rate_limits() -> Iterator[None]:
    rate_limiter.clear()
    yield
    rate_limiter.clear()


@pytest.fixture(scope="session", autouse=True)
def roll_key(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Ed25519PrivateKey]:
    """
    SR-02: a signing key made for this test run. The API checks roll records
    with its public key, so the development keys in backend/keys/ are never used.
    """
    key = Ed25519PrivateKey.generate()
    public_path = tmp_path_factory.mktemp("roll_keys") / "roll_public.pem"
    public_path.write_bytes(
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(settings, "roll_public_key_path", public_path)
        yield key


@pytest.fixture(scope="session", autouse=True)
def delegate_keys(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Ed25519PrivateKey]]:
    """
    SR-07: the three delegates' keys for this test run, made by the delegate script itself,
    with the API's keyring setting pointed at their keyring. backend/keys/ is never touched.
    """
    folder = tmp_path_factory.mktemp("delegates")
    keys = ensure_delegate_keys(folder)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(settings, "delegate_keyring_path", folder / "keyring.json")
        yield keys


@dataclass
class Clock:
    now: datetime

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """
    SR-01: one controllable time for sign in, sessions, lockouts and code checks.
    SR-02: moved here from test_sr01_auth.py so the eligibility tests share it,
    and it now sets the time the ballot router sees too.
    """
    fake = Clock(utc_now())
    # SR-07: the ballot definition module and the delegate script read the same clock
    for module in (security, deps, auth, ballot, ballot_definitions, ballot_definition_script):
        monkeypatch.setattr(module, "utc_now", lambda: fake.now)
    return fake


# ---------------------------------------------------------------
# Test data
# ---------------------------------------------------------------


@dataclass
class ElectionData:
    election: Election
    divisions: dict[str, Division]
    candidates: dict[str, list[Candidate]]


@pytest.fixture
def election(db_session: Session, delegate_keys: dict[str, Ed25519PrivateKey]) -> ElectionData:
    """An open election with two divisions of three candidates each, and an active signed definition (SR-07)."""
    now = utc_now()
    election = Election(
        name="Test election",
        status=ElectionStatus.OPEN,
        starts_at=now - timedelta(days=1),
        ends_at=now + timedelta(days=1),
        # SR-02: ages are worked out on this fixed date
        polling_date=POLLING_DATE,
    )
    divisions = {name: Division(name=name, state="Victoria") for name in ("Northgate", "Southvale")}
    db_session.add(election)
    db_session.add_all(divisions.values())
    db_session.flush()
    candidates = {
        name: [
            Candidate(
                election_id=election.id,
                division_id=division.id,
                given_name=given,
                surname=surname,
                party=party,
                ballot_position=position,
            )
            for position, (given, surname, party) in enumerate(CANDIDATE_NAMES, start=1)
        ]
        for name, division in divisions.items()
    }
    db_session.add_all([c for rows in candidates.values() for c in rows])
    db_session.commit()
    # SR-07: ballots now come only from a signed definition, so every test election has version 1,
    # signed by two delegates and stored directly as fixture data (as the seed does). Valid from
    # 2000 to 2100, so tests that move the clock still have a valid definition.
    payload = build_payload(db_session, election, DEFINITION_VALID_FROM, DEFINITION_VALID_UNTIL)
    signatures = [sign(delegate_keys[d], payload) for d in ("delegate_a", "delegate_b")]
    store_active(db_session, election.id, payload, signatures, election.starts_at - timedelta(hours=25))
    db_session.commit()
    return ElectionData(election=election, divisions=divisions, candidates=candidates)


@dataclass
class Person:
    """The details a person types into step 1 of registration."""

    given_name: str
    surname: str
    date_of_birth: str
    postcode: str
    enrolment_code: str
    division: str
    roll_id: uuid.UUID = field(default_factory=uuid.uuid4)

    def verify_body(self, **changes: str) -> dict[str, str]:
        body = {
            "given_name": self.given_name,
            "surname": self.surname,
            "date_of_birth": self.date_of_birth,
            "postcode": self.postcode,
            "enrolment_code": self.enrolment_code,
        }
        return body | changes


@pytest.fixture
def make_person(db_session: Session, election: ElectionData, roll_key: Ed25519PrivateKey) -> Callable[..., Person]:
    """Puts a person on the roll, with an enrolment code, and returns their details."""
    counter = itertools.count(1)

    # SR-02: date_of_birth added, so eligibility tests can choose an age
    def make(
        *,
        division: str = "Northgate",
        enrolled: bool = True,
        registered: bool = False,
        code_expires_in: timedelta = timedelta(days=30),
        code_attempts: int = 0,
        date_of_birth: str = "1985-06-15",
    ) -> Person:
        n = next(counter)
        person = Person(
            given_name="Alex",
            surname=f"Tester{n}",
            date_of_birth=date_of_birth,
            postcode="3000",
            enrolment_code=f"TEST-CODE-{n:04d}",
            division=division,
        )
        entry = ElectoralRollEntry(
            id=person.roll_id,
            roll_lookup=roll_lookup(person.given_name, person.surname, person.date_of_birth, person.postcode),
            full_name_enc=encrypt(f"{person.given_name} {person.surname}", "electoral_roll.full_name"),
            address_enc=encrypt("1 Test Street, Carlton VIC 3053", "electoral_roll.address"),
            date_of_birth_enc=encrypt(person.date_of_birth, "electoral_roll.date_of_birth"),
            postcode_enc=encrypt(person.postcode, "electoral_roll.postcode"),
            division_id=election.divisions[division].id,
            enrolled=enrolled,
            enrolment_code_hash=enrolment_code_hash(person.enrolment_code),
            code_expires_at=utc_now() + code_expires_in,
            code_attempts=code_attempts,
            registered_at=utc_now() if registered else None,
        )
        # SR-02: every test roll record is signed, as scripts/sign_roll.py would sign it
        entry.record_signature = sign_record(roll_key, entry)
        db_session.add(entry)
        db_session.commit()
        return person

    return make


@dataclass
class RegisteredVoter:
    username: str
    password: str
    totp_secret: str
    full_name: str
    division: str
    account_id: uuid.UUID

    def code(self) -> str:
        # SR-03: the app's clock, so sign_in also works while the clock fixture controls time
        return pyotp.TOTP(self.totp_secret).at(security.utc_now())


@pytest.fixture
def make_voter(db_session: Session, make_person: Callable[..., Person]) -> Callable[..., RegisteredVoter]:
    """A person on the roll who has already registered, as the registration flow would leave them."""
    counter = itertools.count(1)

    # SR-02: date_of_birth passed on to the roll record
    def make(
        *, division: str = "Northgate", enrolled: bool = True, official: bool = False, date_of_birth: str = "1985-06-15"
    ) -> RegisteredVoter:
        n = next(counter)
        person = (
            None
            if official
            else make_person(division=division, enrolled=enrolled, registered=True, date_of_birth=date_of_birth)
        )
        voter = RegisteredVoter(
            username=f"official.{n}" if official else f"voter.{n}",
            password=f"long enough password {n}",
            totp_secret=new_totp_secret(),
            # SR-05: staff see their username after sign in, so that is their display name here too
            full_name=f"official.{n}" if person is None else f"{person.given_name} {person.surname}",
            division=division,
            account_id=uuid.uuid4(),
        )
        db_session.add(
            Account(
                id=voter.account_id,
                username=voter.username,
                password_hash=hash_password(voter.password),
                # SR-05: "official" now means a polling official, who has no roll entry
                role=AccountRole.POLLING_OFFICIAL if official else AccountRole.ELECTOR,
                roll_id=None if person is None else person.roll_id,
                totp_secret_enc=encrypt(voter.totp_secret, "accounts.totp_secret"),
            )
        )
        db_session.commit()
        return voter

    return make


@pytest.fixture
def make_staff(db_session: Session) -> Callable[[str], RegisteredVoter]:
    """
    SR-05: a staff account, made by the create_staff script's own function.
    SR-06: moved here from test_sr05_access_control.py so the SR-06 tests share it.
    """
    counter = itertools.count(1)

    def make(role: str) -> RegisteredVoter:
        n = next(counter)
        username, password = f"{role}.{n}", f"staff password number {n}"
        _, secret = create_staff(db_session, username, role, password)
        account_id = db_session.scalars(select(Account.id).where(Account.username == username)).one()
        return RegisteredVoter(username, password, secret, full_name=username, division="", account_id=account_id)

    return make


@pytest.fixture
def sign_in(client: TestClient) -> Callable[[RegisteredVoter], Response]:
    """Signs a voter in through both parts and returns the response to the code step."""

    def go(voter: RegisteredVoter) -> Response:
        client.post("/api/auth/login", json={"username": voter.username, "password": voter.password})
        return client.post("/api/auth/verify", json={"otp_code": voter.code()})

    return go
