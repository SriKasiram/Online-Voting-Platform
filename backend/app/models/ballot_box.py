"""
The anonymous side of the system: one-time ballot tokens and the ballots.

These tables must never hold anything that could identify a voter: no account
or roll reference, and no timestamp that could be matched against
voter_participation.marked_at. tests/test_ballot_secrecy.py fails if a column
is added here, so every new column gets a deliberate review.

ciphertext, nonce and token_hash hold plain placeholder values in Stage 2.
"""

import uuid

from sqlalchemy import ForeignKey, false, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class BallotToken(Base):
    __tablename__ = "ballot_tokens"

    token_hash: Mapped[bytes] = mapped_column(primary_key=True)
    election_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("elections.id"))
    division_id: Mapped[int] = mapped_column(ForeignKey("divisions.id"))
    used: Mapped[bool] = mapped_column(default=False, server_default=false())


class Ballot(Base):
    __tablename__ = "ballots"

    # Random (version 4) UUID, so an id never reveals the order ballots arrived in
    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    election_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("elections.id"))
    division_id: Mapped[int] = mapped_column(ForeignKey("divisions.id"))
    ciphertext: Mapped[bytes]
    nonce: Mapped[bytes]
    key_id: Mapped[str]
