"""Election setup: the election, its divisions, the candidates and each division's ballot paper."""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Enum, ForeignKey, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ElectionStatus(enum.StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    TALLIED = "TALLIED"


class Election(Base):
    __tablename__ = "elections"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str]
    status: Mapped[ElectionStatus] = mapped_column(Enum(ElectionStatus, name="election_status"))
    starts_at: Mapped[datetime]
    ends_at: Mapped[datetime]


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

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    election_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("elections.id"))
    division_id: Mapped[int] = mapped_column(ForeignKey("divisions.id"))
    definition: Mapped[dict[str, Any]]
    # Placeholder: empty until signing is added
    signature: Mapped[bytes | None]
