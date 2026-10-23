"""The seed script: idempotent, and --reset-reviewer lets the reviewer register again."""

from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Account, BallotDefinition, Candidate, Division, Election, ElectoralRollEntry
from app.security import enrolment_code_hash, roll_lookup, utc_now
from scripts.seed import (
    CODE_VALID_DAYS,
    REVIEWER_DATE_OF_BIRTH,
    REVIEWER_DIVISION,
    REVIEWER_ENROLMENT_CODE,
    REVIEWER_GIVEN_NAME,
    REVIEWER_POSTCODE,
    REVIEWER_SURNAME,
    reset_reviewer,
    seed,
    seed_demo_electors,
)

REVIEWER = {
    "given_name": REVIEWER_GIVEN_NAME,
    "surname": REVIEWER_SURNAME,
    "date_of_birth": REVIEWER_DATE_OF_BIRTH,
    "postcode": REVIEWER_POSTCODE,
    "enrolment_code": REVIEWER_ENROLMENT_CODE,
}


def counts(db: Session) -> dict[str, int]:
    tables = (Election, Division, Candidate, BallotDefinition, ElectoralRollEntry, Account)
    return {t.__tablename__: db.scalar(select(func.count()).select_from(t)) for t in tables}


def reviewer_entry(db: Session) -> ElectoralRollEntry:
    db.expire_all()
    lookup = roll_lookup(REVIEWER_GIVEN_NAME, REVIEWER_SURNAME, REVIEWER_DATE_OF_BIRTH, REVIEWER_POSTCODE)
    return db.scalars(select(ElectoralRollEntry).where(ElectoralRollEntry.roll_lookup == lookup)).one()


def register_reviewer(client: TestClient) -> None:
    assert client.post("/api/register/verify", json=REVIEWER).status_code == 204
    secret = client.post(
        "/api/register/account", json={"username": "reviewer", "password": "reviewer password 1"}
    ).json()["secret"]
    assert client.post("/api/register/confirm", json={"otp_code": pyotp.TOTP(secret).now()}).status_code == 204


def test_seed_is_idempotent(db_session: Session) -> None:
    assert seed(db_session) is True
    first = counts(db_session)

    assert seed(db_session) is False

    assert counts(db_session) == first
    assert first == {
        "elections": 1,
        "divisions": 3,
        "candidates": 15,
        "ballot_definitions": 1,  # SR-07: one signed version for the whole election, not one row per division
        "electoral_roll": 1,
        "accounts": 0,
    }


def test_every_seed_run_refreshes_the_code_expiry(db_session: Session) -> None:
    seed(db_session)
    reviewer_entry(db_session).code_expires_at = utc_now() + timedelta(days=1)
    db_session.commit()

    seed(db_session)

    assert reviewer_entry(db_session).code_expires_at > utc_now() + timedelta(days=CODE_VALID_DAYS - 1)


def test_demo_electors_are_added_once_in_the_reviewers_division_and_can_register(
    client: TestClient, db_session: Session
) -> None:
    """SR-17: --demo-electors adds fake electors for a count demo, only once, each able to register; 1 to 9 only."""
    seed(db_session)

    electors = seed_demo_electors(db_session, 3)

    assert seed_demo_electors(db_session, 3) == electors
    assert counts(db_session)["electoral_roll"] == 4
    divisions = db_session.scalars(select(Division.name).join(ElectoralRollEntry, ElectoralRollEntry.division_id == Division.id))
    assert set(divisions) == {REVIEWER_DIVISION}
    assert client.post("/api/register/verify", json=electors[1]).status_code == 204
    for wrong in (0, 10):
        with pytest.raises(SystemExit):
            seed_demo_electors(db_session, wrong)


def test_reviewer_can_register_with_the_seeded_details(client: TestClient, db_session: Session) -> None:
    seed(db_session)

    register_reviewer(client)

    assert reviewer_entry(db_session).registered_at is not None


def test_reset_reviewer_restores_the_entry(client: TestClient, db_session: Session) -> None:
    seed(db_session)
    register_reviewer(client)
    # Sign in too, so the reset has a live session to clear
    client.post("/api/auth/login", json={"username": "reviewer", "password": "reviewer password 1"})

    reset_reviewer(db_session)

    entry = reviewer_entry(db_session)
    assert db_session.scalar(select(func.count()).select_from(Account)) == 0
    assert entry.registered_at is None
    assert entry.code_attempts == 0
    assert entry.enrolment_code_hash == enrolment_code_hash(REVIEWER_ENROLMENT_CODE)
    assert entry.code_expires_at is not None and entry.code_expires_at > utc_now() + timedelta(days=CODE_VALID_DAYS - 1)
    # And the code works again (SR-10: over HTTPS, like every client)
    assert TestClient(client.app, base_url="https://testserver").post("/api/register/verify", json=REVIEWER).status_code == 204
