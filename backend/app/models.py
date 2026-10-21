"""
Every table, in three groups that must stay apart:

- Election setup: the election, divisions, candidates and ballot papers.
- Voter identity: the roll, accounts, sign in, and the record of who has voted.
- The anonymous ballot box: one-time ballot tokens and the ballots.

Nothing in the ballot box may point to voter identity: no account or roll
reference, and no timestamp that could be matched against
voter_participation.marked_at. tests/test_ballot_secrecy.py fails if a column
is added there, so every new column gets a deliberate review.

Protected columns (helpers in app/security.py): *_enc columns are AES-GCM
encrypted, password_hash is Argon2id, roll_lookup and enrolment_code_hash are
keyed hashes, and the token *_hash columns hold SHA-256 hashes of the cookie
values. Still placeholders: ballots.ciphertext holds plain JSON, and
ballot_definitions.signature is empty.
"""

import enum
import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import BigInteger, Enum, ForeignKey, UniqueConstraint, false, func, text
from sqlalchemy.dialects.postgresql import CITEXT
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))


# ---------------------------------------------------------------
# Election setup
# ---------------------------------------------------------------


class ElectionStatus(enum.StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    TALLIED = "TALLIED"


class Election(Base):
    __tablename__ = "elections"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str]
    status: Mapped[ElectionStatus] = mapped_column(Enum(ElectionStatus, name="election_status"))
    starts_at: Mapped[datetime]
    ends_at: Mapped[datetime]
    # SR-02: the day a voter's age is worked out on, whenever they vote
    polling_date: Mapped[date]


class Division(Base):
    __tablename__ = "divisions"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(unique=True)
    state: Mapped[str]


class Candidate(Base):
    __tablename__ = "candidates"
    # Two candidates cannot share a place on the same ballot paper
    __table_args__ = (UniqueConstraint("election_id", "division_id", "ballot_position"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    election_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("elections.id"))
    division_id: Mapped[int] = mapped_column(ForeignKey("divisions.id"))
    # Kept apart because the ballot paper prints SURNAME, Given names
    given_name: Mapped[str]
    surname: Mapped[str]
    party: Mapped[str]
    ballot_position: Mapped[int]


class BallotDefinition(Base):
    """The ballot paper for one division. A later stage signs it so voters can trust it."""

    __tablename__ = "ballot_definitions"
    __table_args__ = (UniqueConstraint("election_id", "division_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    election_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("elections.id"))
    division_id: Mapped[int] = mapped_column(ForeignKey("divisions.id"))
    definition: Mapped[dict[str, Any]]
    signature: Mapped[bytes | None]


# ---------------------------------------------------------------
# Voter identity. Nothing here may point to a ballot.
# ---------------------------------------------------------------


class AccountRole(enum.StrEnum):
    VOTER = "VOTER"
    ELECTION_OFFICIAL = "ELECTION_OFFICIAL"


class ElectoralRollEntry(Base):
    __tablename__ = "electoral_roll"

    id: Mapped[uuid.UUID] = uuid_pk()
    # Blind index: keyed hash of the normalised given name, surname, date of
    # birth and postcode, so registration finds an entry without decrypting any
    roll_lookup: Mapped[bytes] = mapped_column(unique=True)
    full_name_enc: Mapped[bytes]
    address_enc: Mapped[bytes]
    # Empty only on entries created before registration existed
    date_of_birth_enc: Mapped[bytes | None]
    postcode_enc: Mapped[bytes | None]
    # SR-02: may be empty, for an elector not (or no longer) assigned to a division. They get no ballot.
    division_id: Mapped[int | None] = mapped_column(ForeignKey("divisions.id"))
    enrolled: Mapped[bool]
    # The one-time enrolment code, as a keyed hash. Cleared once used.
    enrolment_code_hash: Mapped[bytes | None]
    code_expires_at: Mapped[datetime | None]
    # Wrong codes so far. At ENROLMENT_CODE_MAX_ATTEMPTS the code is locked.
    code_attempts: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    registered_at: Mapped[datetime | None]
    # SR-02: Ed25519 signature over the eligibility fields (app/roll_signing.py). Empty until
    # python -m scripts.sign_roll runs, and an empty one fails every check.
    record_signature: Mapped[bytes | None]


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = uuid_pk()
    # citext, so "Voter.One" and "voter.one" are the same username
    username: Mapped[str] = mapped_column(CITEXT(), unique=True)
    password_hash: Mapped[str]
    role: Mapped[AccountRole] = mapped_column(Enum(AccountRole, name="account_role"))
    # Election officials are not on the roll. UNIQUE: one account per person on the roll.
    roll_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("electoral_roll.id"), unique=True)
    totp_secret_enc: Mapped[bytes]
    # SR-01: consecutive failed sign-in attempts, at the password or the code step. Reset by a full sign in.
    failed_logins: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    # SR-01: set for LOCK_MINUTES when failed_logins reaches MAX_FAILED_ATTEMPTS
    locked_until: Mapped[datetime | None]
    # SR-01: the last authenticator time step accepted, so a code cannot be used twice
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)


class SessionStage(enum.StrEnum):
    """SR-01: a session opens voting routes only once both sign-in steps have passed."""

    MFA_PENDING = "mfa_pending"
    AUTHENTICATED = "authenticated"


class AuthSession(Base):
    """A sign-in session. Named AuthSession so it is not confused with a SQLAlchemy Session."""

    __tablename__ = "sessions"

    session_id_hash: Mapped[bytes] = mapped_column(primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id"))
    # SR-01: mfa_pending after the password, authenticated after the code
    stage: Mapped[SessionStage] = mapped_column(
        Enum(SessionStage, name="session_stage", values_callable=lambda e: [m.value for m in e])
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]


class RegistrationStage(enum.StrEnum):
    VERIFIED = "verified"
    ACCOUNT_PENDING = "account_pending"


class RegistrationSession(Base):
    """
    A registration in progress: the roll entry has been verified, and the new
    account is held here until the voter proves their authenticator app works.
    """

    __tablename__ = "registration_sessions"

    id_hash: Mapped[bytes] = mapped_column(primary_key=True)
    roll_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("electoral_roll.id"))
    stage: Mapped[RegistrationStage] = mapped_column(
        Enum(RegistrationStage, name="registration_stage", values_callable=lambda e: [m.value for m in e])
    )
    username: Mapped[str | None] = mapped_column(CITEXT())
    password_hash: Mapped[str | None]
    totp_secret_enc: Mapped[bytes | None]
    attempts: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]


class VoterParticipation(Base):
    """Records that a voter has voted in an election. Never records how."""

    __tablename__ = "voter_participation"

    # The composite primary key is UNIQUE(account_id, election_id):
    # the database itself refuses a second vote from the same voter
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id"), primary_key=True)
    election_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("elections.id"), primary_key=True)
    marked_at: Mapped[datetime] = mapped_column(server_default=func.now())


# ---------------------------------------------------------------
# The anonymous ballot box. No voter reference and no timestamp, by design.
# ---------------------------------------------------------------


class BallotToken(Base):
    __tablename__ = "ballot_tokens"

    token_hash: Mapped[bytes] = mapped_column(primary_key=True)
    election_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("elections.id"))
    division_id: Mapped[int] = mapped_column(ForeignKey("divisions.id"))
    used: Mapped[bool] = mapped_column(default=False, server_default=false())


class Ballot(Base):
    __tablename__ = "ballots"

    # Random (version 4) UUID, so an id never reveals the order ballots arrived in
    id: Mapped[uuid.UUID] = uuid_pk()
    election_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("elections.id"))
    division_id: Mapped[int] = mapped_column(ForeignKey("divisions.id"))
    ciphertext: Mapped[bytes]
    nonce: Mapped[bytes]
    key_id: Mapped[str]


# ---------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------


class AuditLogEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    event_type: Mapped[str]
    actor: Mapped[str]
    details: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'::jsonb"))
    # UNIQUE prev_hash stops two entries from claiming the same predecessor
    prev_hash: Mapped[bytes] = mapped_column(unique=True)
    hash: Mapped[bytes]
