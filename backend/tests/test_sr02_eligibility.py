"""
SR-02: before each ballot, the voter's Ed25519-signed roll record is verified,
and only an enrolled voter with a division who is 18 or over on polling day
gets a ballot. The API refuses to start if any roll record fails its check.

Test roll data is signed with the run's key (the roll_key fixture), polling
dates are fixed, and the clock fixture fixes "today", so nothing here depends
on the real date.
"""

import json
from datetime import UTC, date, datetime, timedelta

import pyotp
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from helpers import outcome, start_api
from app.config import BACKEND_DIR, settings
from app.eligibility import age_on
from app.main import app
from app.models import (
    Account,
    AuditLogEntry,
    Ballot,
    BallotToken,
    ElectoralRollEntry,
    ParticipationState,
    VoterParticipation,
)
from app.roll_signing import DOMAIN_TAG, load_public_key, public_key, record_message, verify_record
from app.security import encrypt
from scripts.seed import seed
from scripts.sign_roll import load_or_create_private_key, sign_all, sign_record

POLLING_DAY = date(2027, 5, 15)
# Every denial looks like this to the voter, whatever the reason
NOT_ENROLLED = (403, {"detail": "not_enrolled"})


@pytest.fixture
def polling_day(db_session: Session, election, clock):
    """SR-02: sets the open election's polling date, with the clock fixed inside the voting period."""
    clock.now = datetime(2027, 5, 1, 1, 0, tzinfo=UTC)

    def set_day(day: date) -> None:
        e = election.election
        e.starts_at, e.ends_at, e.polling_date = clock.now - timedelta(days=1), clock.now + timedelta(days=30), day
        db_session.commit()

    set_day(POLLING_DAY)
    return set_day


def sign_in_now(client: TestClient, voter, clock) -> None:
    client.post("/api/auth/login", json={"username": voter.username, "password": voter.password})
    code = pyotp.TOTP(voter.totp_secret).at(clock.now)
    assert client.post("/api/auth/verify", json={"otp_code": code}).status_code == 200


def ballot_for(client: TestClient, voter, clock):
    sign_in_now(client, voter, clock)
    return client.get("/api/ballot")


def roll_of(db_session: Session, voter) -> ElectoralRollEntry:
    db_session.expire_all()
    return db_session.get_one(ElectoralRollEntry, db_session.get_one(Account, voter.account_id).roll_id)


def resign(db_session: Session, key: Ed25519PrivateKey, entry: ElectoralRollEntry, **changes) -> None:
    """Changes signed fields the proper way: through the signing key."""
    for name, value in changes.items():
        setattr(entry, name, value)
    entry.record_signature = sign_record(key, entry)
    db_session.commit()


def tamper(db_session: Session, entry: ElectoralRollEntry, **changes) -> None:
    """Changes fields directly in the database, without the signing key."""
    for name, value in changes.items():
        setattr(entry, name, value)
    db_session.commit()


def denials(db_session: Session) -> list[str]:
    rows = db_session.scalars(
        select(AuditLogEntry).where(AuditLogEntry.event_type == "ELIGIBILITY_DENIED").order_by(AuditLogEntry.id)
    )
    # SR-16: the reason is a structured field now
    return [row.reason for row in rows]


def last_audit(db_session: Session) -> AuditLogEntry:
    return db_session.scalars(select(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(1)).one()


# ---------------------------------------------------------------
# Age on polling day
# ---------------------------------------------------------------


def test_turns_18_on_polling_day_is_eligible(client: TestClient, make_voter, clock, polling_day) -> None:
    """SR-02 test 1: an 18th birthday on polling day itself is old enough."""
    voter = make_voter(date_of_birth="2009-05-15")

    assert ballot_for(client, voter, clock).status_code == 200


def test_turns_18_the_day_after_polling_day_is_denied(
    client: TestClient, db_session: Session, make_voter, clock, polling_day
) -> None:
    """SR-02 test 2: an 18th birthday the day after polling day is too late, and no ballot token is issued."""
    voter = make_voter(date_of_birth="2009-05-16")

    assert outcome(ballot_for(client, voter, clock)) == NOT_ENROLLED
    assert denials(db_session) == ["under_age"]
    assert db_session.scalar(select(func.count()).select_from(BallotToken)) == 0


@pytest.mark.parametrize(("day", "status_code"), [(date(2026, 2, 28), 403), (date(2026, 3, 1), 200)])
def test_born_on_29_february(
    client: TestClient, make_voter, clock, polling_day, day: date, status_code: int
) -> None:
    """SR-02 test 3: born 29 February 2008, so still 17 on 28 February 2026 and 18 on 1 March 2026."""
    voter = make_voter(date_of_birth="2008-02-29")
    polling_day(day)

    assert ballot_for(client, voter, clock).status_code == status_code


def test_age_is_worked_out_on_polling_day_not_today(
    client: TestClient, db_session: Session, make_voter, clock, polling_day
) -> None:
    """SR-02 test 4: 18 today, but 17 on the polling date that has already passed: denied."""
    clock.now = datetime(2027, 5, 20, 1, 0, tzinfo=UTC)
    polling_day(POLLING_DAY)
    voter = make_voter(date_of_birth="2009-05-20")

    assert age_on(date(2009, 5, 20), clock.now.date()) == 18
    assert outcome(ballot_for(client, voter, clock)) == NOT_ENROLLED
    assert denials(db_session) == ["under_age"]


# ---------------------------------------------------------------
# Enrolment and division
# ---------------------------------------------------------------


def test_eligible_voter_gets_their_divisions_ballot(
    client: TestClient, election, make_voter, clock, polling_day
) -> None:
    """SR-02 test 5: enrolled, 18 or over, with a division: the ballot is that division's."""
    voter = make_voter(division="Southvale")

    ballot = ballot_for(client, voter, clock).json()

    assert ballot["division_name"] == "Southvale"
    assert [c["id"] for c in ballot["candidates"]] == [c.id for c in election.candidates["Southvale"]]


def test_removed_from_the_roll_after_registering_is_denied(
    client: TestClient, db_session: Session, make_voter, clock, polling_day, roll_key
) -> None:
    """SR-02 test 6: enrolment ended, and the record properly re-signed: denied."""
    voter = make_voter()
    resign(db_session, roll_key, roll_of(db_session, voter), enrolled=False)

    assert outcome(ballot_for(client, voter, clock)) == NOT_ENROLLED
    assert denials(db_session) == ["not_enrolled"]


def test_division_removed_after_registering_is_denied(
    client: TestClient, db_session: Session, make_voter, clock, polling_day, roll_key
) -> None:
    """SR-02 test 7: no division any more, and the record properly re-signed: denied."""
    voter = make_voter()
    resign(db_session, roll_key, roll_of(db_session, voter), division_id=None)

    assert outcome(ballot_for(client, voter, clock)) == NOT_ENROLLED
    assert denials(db_session) == ["no_division"]


def test_division_sent_by_the_browser_is_ignored(
    client: TestClient, election, make_voter, clock, polling_day
) -> None:
    """SR-02 test 8: a division in the query, a header or the body changes nothing. The roll's division is used."""
    voter = make_voter(division="Northgate")
    other = election.divisions["Southvale"]
    sign_in_now(client, voter, clock)
    headers = {"X-Division-Id": str(other.id)}

    ballot = client.get(f"/api/ballot?division_id={other.id}&division=Southvale", headers=headers).json()
    submitted = client.post(
        "/api/ballot/submit",
        json={
            "ballot_token": ballot["ballot_token"],
            "ranked_candidate_ids": [c.id for c in election.candidates["Northgate"]],
            "division_id": other.id,
        },
        headers=headers,
    )

    assert ballot["division_name"] == "Northgate"
    assert submitted.status_code == 200


def test_submission_is_refused_once_removed_from_the_roll(
    client: TestClient, db_session: Session, make_voter, clock, polling_day, roll_key
) -> None:
    """SR-02: eligibility is checked again when the ballot is submitted, not only when it is issued."""
    voter = make_voter()
    ballot = ballot_for(client, voter, clock).json()
    resign(db_session, roll_key, roll_of(db_session, voter), enrolled=False)

    response = client.post(
        "/api/ballot/submit",
        json={"ballot_token": ballot["ballot_token"], "ranked_candidate_ids": [c["id"] for c in ballot["candidates"]]},
    )

    assert outcome(response) == NOT_ENROLLED
    # SR-03: participation now exists from issue, so check that no vote was recorded instead
    assert db_session.scalar(select(func.count()).select_from(Ballot)) == 0
    assert db_session.scalars(select(VoterParticipation)).one().state == ParticipationState.ISSUED


# ---------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------


def test_division_changed_after_signing_fails_the_signature(
    client: TestClient, db_session: Session, election, make_voter, clock, polling_day
) -> None:
    """SR-02 test 9: looks exactly like not being enrolled. Only the audit entry says bad_signature."""
    voter = make_voter()
    tamper(db_session, roll_of(db_session, voter), division_id=election.divisions["Southvale"].id)

    assert outcome(ballot_for(client, voter, clock)) == NOT_ENROLLED
    entry = db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.event_type == "ELIGIBILITY_DENIED")).one()
    # SR-16: the reason, outcome and role as structured fields
    assert (entry.actor, entry.role, entry.outcome, entry.reason) == (
        f"account:{voter.account_id}",
        "elector",
        "denied",
        "bad_signature",
    )


@pytest.mark.parametrize("field", ["date_of_birth", "enrolled"])
def test_date_of_birth_or_enrolment_changed_after_signing_is_denied(
    client: TestClient, db_session: Session, make_voter, clock, polling_day, field: str
) -> None:
    """SR-02 test 10: making a minor an adult, or an elector enrolled, in the database alone: denied."""
    if field == "date_of_birth":
        voter = make_voter(date_of_birth="2012-01-01")
        tamper(
            db_session,
            roll_of(db_session, voter),
            date_of_birth_enc=encrypt("1990-01-01", "electoral_roll.date_of_birth"),
        )
    else:
        voter = make_voter(enrolled=False)
        tamper(db_session, roll_of(db_session, voter), enrolled=True)

    assert outcome(ballot_for(client, voter, clock)) == NOT_ENROLLED
    assert denials(db_session) == ["bad_signature"]


def test_signature_copied_from_another_record_is_denied(
    client: TestClient, db_session: Session, make_voter, clock, polling_day
) -> None:
    """SR-02 test 11: a valid signature belongs to one record only."""
    other, voter = make_voter(), make_voter()
    tamper(db_session, roll_of(db_session, voter), record_signature=roll_of(db_session, other).record_signature)

    assert outcome(ballot_for(client, voter, clock)) == NOT_ENROLLED
    assert denials(db_session) == ["bad_signature"]


def test_registration_and_voting_changes_keep_the_signature_valid(
    client: TestClient, db_session: Session, make_voter, clock, polling_day
) -> None:
    """SR-02 test 12: registered_at, the enrolment code and voting do not touch the signed fields."""
    voter = make_voter()
    ballot = ballot_for(client, voter, clock).json()
    ranking = [c["id"] for c in ballot["candidates"]]
    assert client.post(
        "/api/ballot/submit", json={"ballot_token": ballot["ballot_token"], "ranked_candidate_ids": ranking}
    ).status_code == 200

    entry = roll_of(db_session, voter)
    tamper(db_session, entry, registered_at=None, code_attempts=3, enrolment_code_hash=None, code_expires_at=None)

    assert verify_record(public_key(), roll_of(db_session, voter))
    assert denials(db_session) == []


def test_signed_message_holds_only_the_eligibility_fields(db_session: Session, make_person) -> None:
    """SR-02: a domain tag, then compact JSON with sorted keys of the five fixed eligibility fields."""
    person = make_person(date_of_birth="2001-02-03")
    message = record_message(db_session.get_one(ElectoralRollEntry, person.roll_id))

    tag, body = message.split(b"\n", 1)
    fields = json.loads(body)

    assert tag == DOMAIN_TAG == b"evoting-roll-record-v1"
    assert sorted(fields) == ["date_of_birth", "division_id", "enrolled", "roll_id", "roll_lookup"]
    assert (fields["roll_id"], fields["date_of_birth"], fields["enrolled"]) == (str(person.roll_id), "2001-02-03", True)
    assert body == json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------
# Start-up check
# ---------------------------------------------------------------


def test_startup_refuses_a_tampered_record(client: TestClient, db_session: Session, election, make_voter) -> None:
    """SR-02 test 13: one record changed without the key: the API refuses to start and audits it.
    SR-16: the failed count is the count field and the cause a reason code (the total is not recorded)."""
    make_voter()
    voter = make_voter()
    tamper(db_session, roll_of(db_session, voter), division_id=election.divisions["Southvale"].id)

    with pytest.raises(RuntimeError, match=r"1 of 2 records"):
        start_api()

    entry = last_audit(db_session)
    assert (entry.event_type, entry.actor, entry.category, entry.outcome, entry.count, entry.reason) == (
        "ROLL_VERIFICATION_FAILED",
        "unknown",
        "configuration",
        "failure",
        1,
        "bad_signature",
    )


@pytest.mark.parametrize("signature", ["none", "another key"])
def test_startup_refuses_a_record_added_without_the_key(
    client: TestClient, db_session: Session, make_person, signature: str
) -> None:
    """SR-02 test 14: a record with no signature, or one made with any other key, stops the start-up."""
    entry = db_session.get_one(ElectoralRollEntry, make_person().roll_id)
    other_key = Ed25519PrivateKey.generate()
    tamper(db_session, entry, record_signature=None if signature == "none" else sign_record(other_key, entry))

    with pytest.raises(RuntimeError):
        start_api()

    assert last_audit(db_session).event_type == "ROLL_VERIFICATION_FAILED"


def test_startup_with_a_valid_roll_starts_and_audits(client: TestClient, db_session: Session, make_voter) -> None:
    """SR-02 test 15: every record checks out: the API starts and records ROLL_VERIFIED with counts only.
    SR-16: the record count is the count field."""
    make_voter()
    make_voter()

    start_api()

    entry = last_audit(db_session)
    assert (entry.event_type, entry.actor, entry.outcome, entry.count, entry.reason) == ("ROLL_VERIFIED", "unknown", "success", 2, None)


def test_startup_refuses_without_the_public_key(
    client: TestClient, db_session: Session, make_voter, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """SR-02: no public key means nothing can be verified, so the API does not start. SR-16: the reason says why."""
    make_voter()
    monkeypatch.setattr(settings, "roll_public_key_path", tmp_path / "missing.pem")

    with pytest.raises(RuntimeError):
        start_api()

    entry = last_audit(db_session)
    assert (entry.count, entry.reason) == (1, "public_key_missing")


# ---------------------------------------------------------------
# Keys and the signing script
# ---------------------------------------------------------------


def test_sign_roll_creates_keys_once_and_signs_every_record(db_session: Session, tmp_path) -> None:
    """SR-02: the script makes a key pair on its first run, reuses it afterwards, and signs the seeded roll."""
    seed(db_session)
    private_path, public_path = tmp_path / "keys" / "roll_private.pem", tmp_path / "keys" / "roll_public.pem"

    key = load_or_create_private_key(private_path, public_path)
    count = sign_all(db_session, key)

    entries = db_session.scalars(select(ElectoralRollEntry)).all()
    assert private_path.exists() and public_path.exists()
    assert count == len(entries) >= 1
    assert all(verify_record(load_public_key(public_path), entry) for entry in entries)
    again = load_or_create_private_key(private_path, public_path)
    assert again.public_key().public_bytes_raw() == key.public_key().public_bytes_raw()


def test_api_code_never_touches_the_private_key() -> None:
    """SR-02: nothing under app/ imports the signing script or reads a private key."""
    forbidden = ("from scripts", "import scripts", "roll_private", "Ed25519PrivateKey", "load_pem_private_key")
    for path in (BACKEND_DIR / "app").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not [word for word in forbidden if word in text], path
