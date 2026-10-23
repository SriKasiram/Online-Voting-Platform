"""
Seed data: the election (divisions, candidates, ballot papers) and one roll
entry for the reviewer to register with. There are no accounts: every voter
registers through the app.

The reviewer's details below are fake test data. They are written down here,
and in the README, only because this is a prototype. A real voter's enrolment
code would arrive by post or email.

Run from the backend folder, with the virtual environment active:
    python -m scripts.seed                    loads the data, safe to repeat
    python -m scripts.seed --reset-reviewer   lets the reviewer register again
    python -m scripts.seed --reset-participation
                                              SR-03: lets the reviewer be issued a ballot again,
                                              if they have not voted (development only)
    python -m scripts.seed --reset            deletes all data, then loads it again

SR-02: every run ends by signing the roll (scripts/sign_roll.py), creating
development keys in backend/keys/ the first time.

SR-07: the election's ballot papers are version 1 of a ballot definition,
signed by two development delegates (scripts/ballot_definition.py). --reset
clears definitions with everything else.
"""

import argparse
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

# SR-16: the development reset is audited as the script that ran it
from app.audit_events import SCRIPT
from app.ballot_definitions import active_definition
from app.db import Base, SessionLocal
from app.models import (
    Account,
    AuthSession,
    Candidate,
    Division,
    Election,
    ElectionStatus,
    ElectoralRollEntry,
    RegistrationSession,
)
from app.participation import reset_issued
from app.security import encrypt, enrolment_code_hash, roll_lookup
from scripts.ballot_definition import build_payload, ensure_delegate_keys, sign, store_active
from scripts.sign_roll import load_or_create_private_key, sign_all

ELECTION_NAME = "House of Representatives"

# Division name and its state
DIVISIONS: dict[str, str] = {
    "Melbourne": "Victoria",
    "Kooyong": "Victoria",
    "Macnamara": "Victoria",
}

# Candidates per division as (given name, surname, party), in ballot paper order.
# Every name and party is invented.
CANDIDATES: dict[str, list[tuple[str, str, str]]] = {
    "Melbourne": [
        ("Hana", "Ortega", "Harbour Party"),
        ("Daniel", "Whitfield", "Rural Alliance"),
        ("Mei-Lin", "Tran", "Green Horizon"),
        ("Samuel", "Okafor", "Independent"),
        ("Isabel", "Carvalho", "Workers Voice"),
        ("Tom", "Kowalski", "Civic Reform"),
    ],
    "Kooyong": [
        ("Priya", "Natarajan", "Civic Reform"),
        ("George", "Whitlock", "Harbour Party"),
        ("Amara", "Osei", "Green Horizon"),
        ("Lachlan", "Brooks", "Independent"),
    ],
    "Macnamara": [
        ("Sofia", "Marchetti", "Workers Voice"),
        ("Ethan", "Nguyen", "Harbour Party"),
        ("Chloe", "Abernethy", "Green Horizon"),
        ("Yusuf", "Rahman", "Rural Alliance"),
        ("Grace", "Delaney", "Independent"),
    ],
}

# The reviewer's roll entry. Fake test data, not a real person or address.
REVIEWER_GIVEN_NAME = "Robin"
REVIEWER_SURNAME = "Reviewer"
REVIEWER_DATE_OF_BIRTH = "1990-01-01"
REVIEWER_POSTCODE = "3000"
REVIEWER_ADDRESS = "1 Example Street, Melbourne VIC 3000"
REVIEWER_DIVISION = "Melbourne"
REVIEWER_ENROLMENT_CODE = "RVWR-7K3M-Q9TX"
# The code expires this long after the seed last ran
CODE_VALID_DAYS = 365


def seed(session: Session) -> bool:
    """Loads the data and commits. Returns False if the election data was already there."""
    now = datetime.now(UTC)
    added = seed_election(session, now)
    seed_reviewer(session, now)
    # SR-07: also gives an election seeded before SR-07 its signed definition
    seed_definition(session)
    session.commit()
    return added


def seed_election(session: Session, now: datetime) -> bool:
    if session.scalar(select(Election).where(Election.name == ELECTION_NAME)) is not None:
        return False

    # SR-07: polls opened an hour ago and close in about a year. starts_at and ends_at are the
    # times polls open and close.
    election = Election(
        name=ELECTION_NAME,
        status=ElectionStatus.OPEN,
        starts_at=now - timedelta(hours=1),
        ends_at=now + timedelta(days=365),
        # SR-02: polling day is the last day of voting
        polling_date=(now + timedelta(days=365)).date(),
    )
    divisions = {name: Division(name=name, state=state) for name, state in DIVISIONS.items()}
    session.add(election)
    session.add_all(divisions.values())
    session.flush()  # assigns the ids used below

    for division_name, entries in CANDIDATES.items():
        division = divisions[division_name]
        candidates = [
            Candidate(
                election_id=election.id,
                division_id=division.id,
                given_name=given_name,
                surname=surname,
                party=party,
                ballot_position=position,
            )
            for position, (given_name, surname, party) in enumerate(entries, start=1)
        ]
        session.add_all(candidates)
    # SR-07: the old unsigned per-division ballot_definitions rows are gone; seed_definition signs them all
    session.flush()
    return True


def seed_definition(session: Session) -> bool:
    """
    SR-07: signs version 1 of the seeded election's ballot definition with
    delegate_a and delegate_b and stores it as active, if it has none.

    Seed fixture data, written directly: the activation script would refuse,
    because the 24-hour rule applies to it and the demo election must already be
    open. activated_at is therefore set to polls open minus 25 hours.
    """
    election = session.scalars(select(Election).where(Election.name == ELECTION_NAME)).one()
    if active_definition(session, election.id) is not None:
        return False
    keys = ensure_delegate_keys()
    activated_at = election.starts_at - timedelta(hours=25)
    payload = build_payload(session, election, valid_from=activated_at, valid_until=election.ends_at)
    store_active(session, election.id, payload, [sign(keys[d], payload) for d in ("delegate_a", "delegate_b")], activated_at)
    return True


def seed_reviewer(session: Session, now: datetime) -> ElectoralRollEntry:
    """Creates the reviewer's roll entry if it is missing, and refreshes the code's expiry."""
    lookup = roll_lookup(REVIEWER_GIVEN_NAME, REVIEWER_SURNAME, REVIEWER_DATE_OF_BIRTH, REVIEWER_POSTCODE)
    entry = session.scalar(select(ElectoralRollEntry).where(ElectoralRollEntry.roll_lookup == lookup))
    if entry is None:
        division = session.scalars(select(Division).where(Division.name == REVIEWER_DIVISION)).one()
        entry = ElectoralRollEntry(
            roll_lookup=lookup,
            full_name_enc=encrypt(f"{REVIEWER_GIVEN_NAME} {REVIEWER_SURNAME}", "electoral_roll.full_name"),
            address_enc=encrypt(REVIEWER_ADDRESS, "electoral_roll.address"),
            date_of_birth_enc=encrypt(REVIEWER_DATE_OF_BIRTH, "electoral_roll.date_of_birth"),
            postcode_enc=encrypt(REVIEWER_POSTCODE, "electoral_roll.postcode"),
            division_id=division.id,
            enrolled=True,
            enrolment_code_hash=enrolment_code_hash(REVIEWER_ENROLMENT_CODE),
        )
        session.add(entry)
    entry.code_expires_at = now + timedelta(days=CODE_VALID_DAYS)
    session.flush()
    return entry


def reset_reviewer(session: Session) -> None:
    """
    Deletes the reviewer's account and restores their entry and code, so they
    can register again. A ballot they already cast stays in the ballot box:
    ballots are not linked to voters, so it cannot be found and removed.
    SR-03: their participation record stays too, because it belongs to the
    roll entry, not the account: a reviewer who voted cannot vote again.
    """
    now = datetime.now(UTC)
    seed_election(session, now)
    entry = seed_reviewer(session, now)

    accounts = select(Account.id).where(Account.roll_id == entry.id)
    # SR-01: half-finished sign ins are sessions now, so AuthSession covers them too
    # SR-03: VoterParticipation is no longer deleted here (see the docstring)
    session.execute(
        delete(AuthSession).where(AuthSession.account_id.in_(accounts)).execution_options(synchronize_session=False)
    )
    for statement in (
        delete(Account).where(Account.roll_id == entry.id),
        delete(RegistrationSession).where(RegistrationSession.roll_id == entry.id),
    ):
        session.execute(statement.execution_options(synchronize_session=False))

    entry.registered_at = None
    entry.code_attempts = 0
    entry.enrolment_code_hash = enrolment_code_hash(REVIEWER_ENROLMENT_CODE)
    entry.code_expires_at = now + timedelta(days=CODE_VALID_DAYS)
    session.commit()


def reset_participation(session: Session) -> str:
    """
    SR-03, development only: clears the reviewer's "issued" ballot, for example
    after reloading the ballot page lost the token, so they can be issued a new
    one. A "voted" reviewer is refused: a cast ballot cannot be undone, by design.
    Returns what it did.
    """
    lookup = roll_lookup(REVIEWER_GIVEN_NAME, REVIEWER_SURNAME, REVIEWER_DATE_OF_BIRTH, REVIEWER_POSTCODE)
    entry = session.scalar(select(ElectoralRollEntry).where(ElectoralRollEntry.roll_lookup == lookup))
    if entry is None:
        return "There is no reviewer roll entry yet. Run python -m scripts.seed first."
    # SR-05: the reset itself now lives in app/participation.py, shared with the admin route.
    # Same outcomes and messages as before.
    # SR-16: the actor is the script that did it, not the reviewer's own account
    result = reset_issued(session, entry.id, actor=SCRIPT, role=SCRIPT)
    if result == "voted":
        raise SystemExit(
            "The reviewer has already voted, and a cast ballot cannot be undone, by design. "
            "To start again, re-seed everything: python -m scripts.seed --reset"
        )
    if result == "not_found":
        return "The reviewer has not been issued a ballot. Nothing to reset."
    return (
        "Cleared the reviewer's issued ballot. They can sign in and be issued a new one. "
        "Only one ballot can still be cast: once it is, any other token is refused."
    )


def reset(session: Session) -> None:
    """Deletes every row in every table, keeping the tables themselves."""
    tables = ", ".join(table.name for table in Base.metadata.sorted_tables)
    session.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    session.commit()


def sign_roll(session: Session) -> None:
    # SR-02: a freshly seeded roll is signed, so the API's start-up check passes
    count = sign_all(session, load_or_create_private_key())
    print(f"Signed {count} electoral roll records with the development key in backend/keys/.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Load the seed data.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--reset", action="store_true", help="delete all data first, including votes cast")
    group.add_argument("--reset-reviewer", action="store_true", help="let the reviewer register again")
    # SR-03: development only, never an API endpoint or a staff screen
    group.add_argument(
        "--reset-participation", action="store_true", help="clear the reviewer's issued ballot, if not yet voted"
    )
    args = parser.parse_args()

    with SessionLocal() as session:
        if args.reset_participation:
            print(reset_participation(session))
            return
        if args.reset_reviewer:
            reset_reviewer(session)
            sign_roll(session)
            print("The reviewer's account is gone and their enrolment code works again.")
            return
        if args.reset:
            reset(session)
            print("Deleted all data.")
        added = seed(session)
        sign_roll(session)

    print("Added the election data." if added else "Election data already present. Nothing duplicated.")
    print(
        f"Reviewer roll entry ready (fake test data): {REVIEWER_GIVEN_NAME} {REVIEWER_SURNAME}, "
        f"born {REVIEWER_DATE_OF_BIRTH}, postcode {REVIEWER_POSTCODE}, enrolment code {REVIEWER_ENROLMENT_CODE}, "
        f"valid for {CODE_VALID_DAYS} days."
    )


if __name__ == "__main__":
    main()
