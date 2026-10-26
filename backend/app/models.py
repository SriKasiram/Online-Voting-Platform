"""
Every table, in three groups that must stay apart:

- Election setup: the election, divisions, candidates and ballot papers.
- Voter identity: the roll, accounts, sign in, and the record of who has voted.
- The anonymous ballot box: one-time ballot tokens and the ballots.

Nothing in the ballot box may point to voter identity: no account or roll
reference. tests/test_ballot_secrecy.py fails if a column is added there, so
every new column gets a deliberate review.

SR-03: voter_participation, ballot_tokens and ballots share no column that
links them. Participation has no timestamp, a token has no elector and the
hash of its receipt reference is the only handle on it (SR-14), and a ballot
has no token, reference or time.

Protected columns (helpers in app/security.py): *_enc columns are AES-GCM
encrypted, password_hash is Argon2id, roll_lookup and enrolment_code_hash are
keyed hashes, and the token *_hash columns hold SHA-256 hashes of the cookie
values. SR-11: ballots.encrypted_payload holds the whole ballot (division and
ranking) encrypted with AES-256-GCM (app/ballot_crypto.py); nothing else
about a ballot is stored in readable form.
SR-07: ballot_definitions hold payloads signed by two delegates (app/ballot_definitions.py).
SR-12: app/stores.py puts every table on the identity side or the ballot side.
The ballot side (ballot_tokens, ballots) has no foreign key, no time column
and no serial id: its election_id is a plain value, so nothing joins it to the
identity side, and no timestamp can be matched against the audit log.
"""

import enum
import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, Enum, ForeignKey, Index, SmallInteger, UniqueConstraint, false, func, text
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
    # VULN-05: HMAC of the election and the ballot token issued in this session (app/security.py
    # ballot_binding), so the token works in this session only. It equals no ballot-side value.
    ballot_token_mac: Mapped[bytes | None]


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
    # VULN-06: taken usernames tried at step 2, at most MAX_USERNAME_ATTEMPTS
    username_attempts: Mapped[int] = mapped_column(default=0, server_default=text("0"))


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
    and no issue time. When the token is used its receipt is recorded, and is
    the only way to find the row again (SR-14: as a hash only).
    SR-12: no expiry and no "used at" time any more: those matched the audit
    log's issue and acceptance times to the second. A token is usable only
    while its election is open and the elector is signed in.
    SR-14: the receipt reference itself is never stored. It is derived from the
    token the client presents, and only its SHA-256 is kept, so the row can
    confirm a retry but cannot give anyone the reference.
    """

    __tablename__ = "ballot_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()
    # SR-12: a plain value, no foreign key: the ballot side does not join the identity side
    election_id: Mapped[uuid.UUID]
    # SHA-256 of the token as hex. The token itself is never stored.
    token_hash: Mapped[str] = mapped_column(unique=True)
    # SR-14: "used" on its own, so a token used before SR-14 (no receipt hash) still counts as used
    consumed: Mapped[bool] = mapped_column(default=False, server_default=false())
    # SR-14: SHA-256 (hex) of the reference returned to the client; empty until the token is used
    receipt_hash: Mapped[str | None]


class Ballot(Base):
    __tablename__ = "ballots"

    # Random (version 4) UUID, so an id never reveals the order ballots arrived in.
    # SR-11: chosen by the application before the INSERT, because it is part of the AES-GCM associated data.
    id: Mapped[uuid.UUID] = uuid_pk()
    # SR-12: a plain value, no foreign key: the ballot side does not join the identity side
    election_id: Mapped[uuid.UUID]
    # SR-11: the division and the ranking, encrypted: version byte, nonce, ciphertext and tag.
    # The division is ballot content too, so it has no readable column any more.
    encrypted_payload: Mapped[bytes]


class PendingBallot(Base):
    """
    VULN-01: an accepted ballot waiting for its SR-13 seal, with exactly the columns of ballots. The
    accept transaction writes here, so the row shares an xmin with the elector's participation and
    audit rows; the seal copies it into ballots in ballot id order, in a subtransaction of its own,
    deletes it here, and then VACUUM FULL removes the dead row from disk. So a ballot is linkable
    through system columns only while it is held, never once sealed.
    VULN-02: a trigger refuses every UPDATE, and every DELETE unless ballots already holds an
    identical copy. There is no bypass flag.
    """

    __tablename__ = "pending_ballots"

    # SR-11: the id the ciphertext is bound to, kept when the seal copies the ballot
    id: Mapped[uuid.UUID] = uuid_pk()
    # SR-12: a plain value, no foreign key: the ballot side does not join the identity side
    election_id: Mapped[uuid.UUID]
    encrypted_payload: Mapped[bytes]


class BallotChainEntry(Base):
    """
    SR-13: one link of an election's SHA-256 hash chain over its accepted ballots
    (app/ballot_chain.py). Written only by the sealing script, in shuffled
    batches: within a batch the order is the random ballot id, so a position
    says nothing about when a ballot arrived (SR-12). No time, elector, roll,
    session or IP. A database trigger refuses UPDATE and DELETE here and on ballots.
    """

    __tablename__ = "ballot_chain"

    # SR-12: a plain value, no foreign key to the identity side
    election_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    # SR-13: assigned by the sealing code, never a database serial, so the database invents no order
    position: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    batch_no: Mapped[int]
    ballot_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ballots.id"), unique=True)
    # SR-13: lowercase hex SHA-256 values
    prev_hash: Mapped[str]
    entry_hash: Mapped[str]


# ---------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------


class AuditLogEntry(Base):
    """
    SR-16: append-only (database triggers refuse UPDATE and DELETE, migration 0013) and written
    only through app/security.py audit(), which allows only the fields of app/audit_events.py.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        # SR-16: a version 2 row carries its fields and no free text
        CheckConstraint(
            "format_version = 1 OR (category IS NOT NULL AND outcome IS NOT NULL AND role IS NOT NULL "
            "AND request_id IS NOT NULL AND details IS NULL)",
            name="v2_fields",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    event_type: Mapped[str]
    actor: Mapped[str]
    # SR-16: free text, kept only for rows written before SR-16; new rows leave it empty (SQL NULL,
    # not JSON null, so the v2_fields check can tell)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True))
    # SR-16: the allow-listed fields, empty on rows written before SR-16 (those are never rewritten)
    category: Mapped[str | None]
    outcome: Mapped[str | None]
    role: Mapped[str | None]
    request_id: Mapped[uuid.UUID | None]
    batch_no: Mapped[int | None]
    count: Mapped[int | None]
    reason: Mapped[str | None]
    # SR-18: the release version of a result release; empty on every other entry
    version: Mapped[int | None]
    # SR-16: which hash formula the row was written with: 1 before SR-16, 2 from SR-16 on.
    # SR-18: 3 from SR-18 on, which also covers `version`; older rows keep their own formula.
    format_version: Mapped[int] = mapped_column(SmallInteger, server_default=text("1"))
    # UNIQUE prev_hash stops two entries from claiming the same predecessor
    prev_hash: Mapped[bytes] = mapped_column(unique=True)
    hash: Mapped[bytes]
