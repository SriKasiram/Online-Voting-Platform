"""
SR-12: the two stores. Every table belongs to exactly one side, and nothing persistent may link
an elector on the identity side to a ballot on the ballot side: no foreign key, no shared
identifier, no time of day and no insertion order. tests/test_sr12_separation.py fails if a table
is added without choosing a side; python -m scripts.audit_separation checks the rest before each
election.
"""

from collections.abc import Iterator
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

IDENTITY_TABLES = frozenset(
    {
        "electoral_roll",  # electors' roll records (personal data, encrypted)
        "accounts",  # elector and staff accounts
        "sessions",  # sign-in sessions, with their exact times
        "registration_sessions",  # registrations in progress
        "voter_participation",  # who was issued a ballot or has voted, never how
        "audit_log",  # the hash-chained audit log: account ids and exact times
        # Public election setup. It holds no ballot content or ballot identifier, and the roll and
        # participation point to it by foreign key, so it stays with the identity side. Ballot-side
        # rows carry the election id only as a plain value, with no foreign key.
        "elections",
        "divisions",
        "candidates",
        "ballot_definitions",
    }
)
# (Sign-in rate-limit counts are identity-side too, but live in memory only: app/security.py.)

BALLOT_TABLES = frozenset(
    {
        "ballots",  # the encrypted ballots (SR-11): random id, election id, ciphertext
        "ballot_tokens",  # one-time token hashes and the receipts they produced
        # SR-13: the hash chain over stored ballots: it names ballots, never electors
        "ballot_chain",
    }
)

# Alembic's own bookkeeping table: schema metadata, on neither side
NOT_APPLICATION_DATA = frozenset({"alembic_version"})


def ballot_rows(db: Session) -> Iterator[Any]:
    """
    SR-12: the one way to read stored ballots in bulk (export, audit, any future count): ordered by
    the random ballot id, never by insertion order or time, so the order reveals nothing.
    """
    yield from db.execute(text("SELECT id, election_id, encrypted_payload FROM ballots ORDER BY id"))
