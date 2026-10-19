"""
Demo data for local development and the tests.

Every person, address and account here is fictional. Running the script again
changes nothing. Add --reset to delete everything first, including votes cast,
and start the demo again.

Run from the backend folder, with the virtual environment active:
    python -m scripts.seed
    python -m scripts.seed --reset
"""

import argparse
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import (
    Account,
    AccountRole,
    BallotDefinition,
    Base,
    Candidate,
    Division,
    Election,
    ElectionStatus,
    ElectoralRollEntry,
)

ELECTION_NAME = "House of Representatives"

# Division name and its state
DIVISIONS: dict[str, str] = {
    "Melbourne": "Victoria",
    "Kooyong": "Victoria",
    "Macnamara": "Victoria",
}

# Candidates per division as (given name, surname, party), in ballot paper order.
# Melbourne matches the frontend's demo ballot.
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

# Electoral roll: (roll lookup, full name, address, division, enrolled)
ROLL: list[tuple[str, str, str, str, bool]] = [
    ("VIC-0001", "Sri Kasiram", "10 Example Street, Carlton VIC 3053", "Melbourne", True),
    ("VIC-0002", "Roshan Kumar", "22 Sample Road, Kew VIC 3101", "Kooyong", True),
    ("VIC-0003", "Sharvari Rajkumar", "5 Test Avenue, St Kilda VIC 3182", "Macnamara", True),
    ("VIC-0004", "Swathi Gajendra", "7 Test Avenue, Kew VIC 3101", "Kooyong", True),
    ("VIC-0005", "Roopsee Kaur", "1 Example Avenue, Southbank VIC 3182", "Melbourne", True),
    ("VIC-0006", "Riley Fictional", "9 Mock Lane, Hawthorn VIC 3122", "Macnamara", False),
]

# Voter accounts: (username, roll lookup). voter.notenrolled is on the roll but not enrolled.
VOTERS: list[tuple[str, str]] = [
    ("srikasiram", "VIC-0001"),
    ("roshan", "VIC-0002"),
    ("sharvari", "VIC-0003"),
    ("swathi", "VIC-0004"),
    ("Roopsee", "VIC-0005"),
    ("voter.notenrolled", "VIC-0006"),
]

OFFICIAL_USERNAME = "official.demo"

# Stage 2 placeholders, stored as plain values: every demo account signs in with
# this password and this 6-digit code. A later stage stores Argon2 password
# hashes and encrypted authenticator (TOTP) secrets instead.
DEMO_PASSWORD = "demo-password"
DEMO_CODE = "123456"


class VoterAccount(NamedTuple):
    username: str
    full_name: str
    division: str
    enrolled: bool


def voter_accounts() -> list[VoterAccount]:
    """Each voter account joined to its roll entry, in the order above. The tests use this too."""
    roll = {lookup: (full_name, division, enrolled) for lookup, full_name, _, division, enrolled in ROLL}
    return [VoterAccount(username, *roll[lookup]) for username, lookup in VOTERS]


def seed(session: Session) -> bool:
    """Adds the demo data and commits. Returns False, changing nothing, if it is already there."""
    if session.scalar(select(Election).where(Election.name == ELECTION_NAME)) is not None:
        return False

    now = datetime.now(UTC)
    election = Election(
        name=ELECTION_NAME,
        status=ElectionStatus.OPEN,
        starts_at=now - timedelta(days=1),
        ends_at=now + timedelta(days=30),
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
        session.flush()

        session.add(
            BallotDefinition(
                election_id=election.id,
                division_id=division.id,
                definition={
                    "election_id": str(election.id),
                    "election_name": ELECTION_NAME,
                    "division_id": division.id,
                    "division_name": division_name,
                    "state_name": division.state,
                    "candidates": [
                        {
                            "id": c.id,
                            "ballot_position": c.ballot_position,
                            "given_name": c.given_name,
                            "surname": c.surname,
                            "party": c.party,
                        }
                        for c in candidates
                    ],
                },
            )
        )

    roll = {
        lookup: ElectoralRollEntry(
            roll_lookup=lookup.encode(),
            full_name_enc=full_name.encode(),
            address_enc=address.encode(),
            division_id=divisions[division_name].id,
            enrolled=enrolled,
        )
        for lookup, full_name, address, division_name, enrolled in ROLL
    }
    session.add_all(roll.values())
    session.flush()

    for username, lookup in VOTERS:
        session.add(
            Account(
                username=username,
                password_hash=DEMO_PASSWORD,
                role=AccountRole.VOTER,
                roll_id=roll[lookup].id,
                totp_secret_enc=DEMO_CODE.encode(),
            )
        )
    session.add(
        Account(
            username=OFFICIAL_USERNAME,
            password_hash=DEMO_PASSWORD,
            role=AccountRole.ELECTION_OFFICIAL,
            roll_id=None,
            totp_secret_enc=DEMO_CODE.encode(),
        )
    )

    session.commit()
    return True


def reset(session: Session) -> None:
    """Deletes every row in every table, keeping the tables themselves."""
    tables = ", ".join(table.name for table in Base.metadata.sorted_tables)
    session.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    session.commit()


def main() -> None:
    parser = argparse.ArgumentParser(description="Load the demo data.")
    parser.add_argument(
        "--reset", action="store_true", help="delete all data first, including votes cast"
    )
    args = parser.parse_args()

    with SessionLocal() as session:
        if args.reset:
            reset(session)
            print("Deleted all data.")
        added = seed(session)

    if not added:
        print("Demo data is already present. Nothing changed. Add --reset to start again.")
        return

    candidates = sum(len(entries) for entries in CANDIDATES.values())
    print(
        f"Added 1 election, {len(DIVISIONS)} divisions, {candidates} candidates, "
        f"{len(ROLL)} roll entries and {len(VOTERS) + 1} accounts."
    )
    print(f"\nDemo sign in: password {DEMO_PASSWORD}, 6-digit code {DEMO_CODE}")
    for voter in voter_accounts():
        note = f"votes in {voter.division}" if voter.enrolled else "on the roll but not enrolled, cannot vote"
        print(f"  {voter.username:<19}{note}")
    print(f"  {OFFICIAL_USERNAME:<19}election official, cannot vote")


if __name__ == "__main__":
    main()
