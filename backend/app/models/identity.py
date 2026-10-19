"""
Voter identity: the electoral roll, accounts, sign-in sessions and the record
of who has voted. Nothing here may point to a ballot, and nothing in
ballot_box.py may point back here.

Placeholder columns hold plain values in Stage 2: password_hash holds the
password itself, totp_secret_enc a fixed 6-digit demo code, the other *_enc
columns plain text, and the *_hash columns the raw tokens. Later stages store
hashes and encrypted values instead.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Enum, ForeignKey, func, text
from sqlalchemy.dialects.postgresql import CITEXT
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AccountRole(enum.StrEnum):
    VOTER = "VOTER"
    ELECTION_OFFICIAL = "ELECTION_OFFICIAL"


class ElectoralRollEntry(Base):
    __tablename__ = "electoral_roll"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    roll_lookup: Mapped[bytes] = mapped_column(unique=True)
    full_name_enc: Mapped[bytes]
    address_enc: Mapped[bytes]
    division_id: Mapped[int] = mapped_column(ForeignKey("divisions.id"))
    enrolled: Mapped[bool]


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    # citext, so "Voter.One" and "voter.one" are the same username
    username: Mapped[str] = mapped_column(CITEXT(), unique=True)
    password_hash: Mapped[str]
    role: Mapped[AccountRole] = mapped_column(Enum(AccountRole, name="account_role"))
    # Election officials are not on the roll, so this can be empty
    roll_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("electoral_roll.id"))
    totp_secret_enc: Mapped[bytes]
    failed_logins: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    locked_until: Mapped[datetime | None]


class AuthSession(Base):
    """A signed-in session. Named AuthSession so it is not confused with a SQLAlchemy Session."""

    __tablename__ = "sessions"

    session_id_hash: Mapped[bytes] = mapped_column(primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]


class LoginChallenge(Base):
    """
    A sign in that passed part 1 (username and password) and now waits for the
    6-digit code. Kept apart from sessions, so a half-finished sign in can never
    be mistaken for a signed-in voter.
    """

    __tablename__ = "login_challenges"

    challenge_id_hash: Mapped[bytes] = mapped_column(primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id"))
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
