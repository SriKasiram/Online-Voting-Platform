"""
Every table, in three groups that must stay apart:

- Election setup: the election, divisions, candidates and ballot papers.
- Voter identity: the roll, accounts, sign in, and the record of who has voted.
- The anonymous ballot box: one-time ballot tokens and the ballots.

Nothing in the ballot box may point to voter identity: no account or roll
reference. tests/test_ballot_secrecy.py fails if a column is added there, so
every new column gets a deliberate review.

SR-03: voter_participation, ballot_tokens and ballots share no column that
links them. Participation has no timestamp, a token has no elector and its
receipt reference is the only handle on it, and a ballot has no token,
reference or time.

Protected columns (helpers in app/security.py): *_enc columns are AES-GCM
encrypted, password_hash is Argon2id, roll_lookup and enrolment_code_hash are
keyed hashes, and the token *_hash columns hold SHA-256 hashes of the cookie
values. Still a placeholder: ballots.ciphertext holds plain JSON.
SR-07: ballot_definitions hold payloads signed by two delegates (app/ballot_definitions.py).
"""

import enum
import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, Enum, ForeignKey, Index, UniqueConstraint, false, func, text
from sqlalchemy.dialects.postgresql import CITEXT, JSONB
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
    """
    SR-07: one signed version of an election's ballot papers, for every division.
    A change is always a new version: the app never updates or deletes a stored
    payload or its signatures. Only is_active moves to the newest version.
    """

    __tablename__ = "ballot_definitions"
    __table_args__ = (
        UniqueConstraint("election_id", "version"),
        # Only one active version per election
        Index("uq_ballot_definitions_one_active", "election_id", unique=True, postgresql_where=text("is_active")),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    election_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("elections.id"))
    version: Mapped[int]
    # The exact canonical JSON that was signed. Verified as stored, never re-serialised.
    payload: Mapped[str]
    # [{"key_id": ..., "signature": base64}, ...]
    signatures: Mapped[list[dict[str, str]]] = mapped_column(JSONB)
    is_active: Mapped[bool] = mapped_column(default=False, server_default=false())
    activated_at: Mapped[datetime]


# ---------------------------------------------------------------
# Voter identity. Nothing here may point to a ballot.
# ---------------------------------------------------------------


class AccountRole(enum.StrEnum):
    """SR-05: the implemented roles. What each may do is in app/rbac.py."""

    ELECTOR = "elector"
    POLLING_OFFICIAL = "polling_official"
    AUDITOR = "auditor"


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
    # SR-05: only known roles, and an elector always has a roll entry while staff never do
    __table_args__ = (
        CheckConstraint("role IN ('elector', 'polling_official', 'auditor')", name="role_valid"),
        CheckConstraint(
            "(role = 'elector' AND roll_id IS NOT NULL) OR (role <> 'elector' AND roll_id IS NULL)", name="role_roll"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    # citext, so "Voter.One" and "voter.one" are the same username
    username: Mapped[str] = mapped_column(CITEXT(), unique=True)
    password_hash: Mapped[str]
    # SR-05: text checked by role_valid, read from the database on every request, never from a session
    role: Mapped[AccountRole] = mapped_column(
        Enum(AccountRole, native_enum=False, length=20, values_callable=lambda e: [m.value for m in e]),
        default=AccountRole.ELECTOR,
        server_default="elector",
    )
    # Staff are not on the roll. UNIQUE: one account per person on the roll.
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
    # SR-04: set when the session is issued, and changed only by an extension or by an accepted ballot
    expires_at: Mapped[datetime]
    # SR-04: extensions used so far. Each one also gives the session a new identifier.
    extensions: Mapped[int] = mapped_column(default=0, server_default=text("0"))


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


class ParticipationState(enum.StrEnum):
    """SR-03: issued when the elector receives a ballot token, voted once their ballot is accepted."""

    ISSUED = "issued"
    VOTED = "voted"


class VoterParticipation(Base):
    """
    Records that an elector was issued a ballot or has voted in an election. Never records how.
    SR-03: keyed by the roll entry rather than the online account, so every voting channel would
    share it, and it has no timestamp that could be matched against a token or a ballot.
    """

    __tablename__ = "voter_participation"

    # SR-03: the composite primary key is UNIQUE(roll_id, election_id): one row per elector per election
    roll_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("electoral_roll.id"), primary_key=True)
    election_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("elections.id"), primary_key=True)
    state: Mapped[ParticipationState] = mapped_column(
        Enum(ParticipationState, name="participation_state", values_callable=lambda e: [m.value for m in e])
    )


# ---------------------------------------------------------------
# The anonymous ballot box. No voter reference, by design.
# ---------------------------------------------------------------


class BallotToken(Base):
    """
    SR-03: a single-use authorisation to cast one ballot. No elector reference
    and no issue time. receipt_reference is set when the token is used, and is
    the only way to find the row again.
    """

    __tablename__ = "ballot_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()
    election_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("elections.id"))
    # SHA-256 of the token as hex. The token itself is never stored.
    token_hash: Mapped[str] = mapped_column(unique=True)
    expires_at: Mapped[datetime]
    consumed_at: Mapped[datetime | None]
    receipt_reference: Mapped[str | None]


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
