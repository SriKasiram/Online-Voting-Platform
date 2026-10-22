"""SR-03: one ballot per elector per election, with single-use, expiring ballot tokens.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-22

voter_participation moves from the online account to the roll entry, gains a
state (issued or voted) and loses marked_at. ballot_tokens is rebuilt: a
random id, the token's SHA-256 as hex, an expiry, when it was used and the
receipt reference. Its division_id and used columns go. Old tokens are
dropped: under the old rules an unused token recorded nothing, and a used
one is already matched by a participation row. ballots is unchanged.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATE = postgresql.ENUM("issued", "voted", name="participation_state", create_type=False)


def upgrade() -> None:
    # SR-03: participation belongs to the elector (roll entry), so every channel shares one record
    op.add_column("voter_participation", sa.Column("roll_id", sa.Uuid(), nullable=True))
    op.execute("UPDATE voter_participation p SET roll_id = a.roll_id FROM accounts a WHERE a.id = p.account_id")
    op.execute("DELETE FROM voter_participation WHERE roll_id IS NULL")
    # SR-03: every existing row recorded a vote
    op.execute("CREATE TYPE participation_state AS ENUM ('issued', 'voted')")
    op.add_column("voter_participation", sa.Column("state", STATE, server_default="voted", nullable=False))
    op.alter_column("voter_participation", "state", server_default=None)
    op.drop_constraint("pk_voter_participation", "voter_participation", type_="primary")
    op.drop_constraint("fk_voter_participation_account_id_accounts", "voter_participation", type_="foreignkey")
    op.drop_column("voter_participation", "account_id")
    # SR-03: no timestamp that could link participation to a token or a ballot
    op.drop_column("voter_participation", "marked_at")
    op.alter_column("voter_participation", "roll_id", nullable=False)
    op.create_primary_key("pk_voter_participation", "voter_participation", ["roll_id", "election_id"])
    op.create_foreign_key(
        "fk_voter_participation_roll_id_electoral_roll", "voter_participation", "electoral_roll", ["roll_id"], ["id"]
    )

    # SR-03: tokens rebuilt with no elector reference and no issue time
    op.drop_table("ballot_tokens")
    op.create_table(
        "ballot_tokens",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("election_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("receipt_reference", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["election_id"], ["elections.id"], name=op.f("fk_ballot_tokens_election_id_elections")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ballot_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_ballot_tokens_token_hash")),
    )


def downgrade() -> None:
    # SR-03: tokens go back to the 0001 shape. Outstanding tokens are dropped.
    op.drop_table("ballot_tokens")
    op.create_table(
        "ballot_tokens",
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("election_id", sa.Uuid(), nullable=False),
        sa.Column("division_id", sa.Integer(), nullable=False),
        sa.Column("used", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.ForeignKeyConstraint(
            ["election_id"], ["elections.id"], name=op.f("fk_ballot_tokens_election_id_elections")
        ),
        sa.ForeignKeyConstraint(
            ["division_id"], ["divisions.id"], name=op.f("fk_ballot_tokens_division_id_divisions")
        ),
        sa.PrimaryKeyConstraint("token_hash", name=op.f("pk_ballot_tokens")),
    )

    # SR-03: back to one row per account. The old schema records only votes, so "issued" rows
    # go, and so does a vote whose roll entry no longer has an account (it cannot be mapped back).
    op.add_column("voter_participation", sa.Column("account_id", sa.Uuid(), nullable=True))
    op.add_column(
        "voter_participation",
        sa.Column("marked_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.execute("UPDATE voter_participation p SET account_id = a.id FROM accounts a WHERE a.roll_id = p.roll_id")
    op.execute("DELETE FROM voter_participation WHERE account_id IS NULL OR state = 'issued'")
    op.drop_constraint("pk_voter_participation", "voter_participation", type_="primary")
    op.drop_constraint("fk_voter_participation_roll_id_electoral_roll", "voter_participation", type_="foreignkey")
    op.drop_column("voter_participation", "roll_id")
    op.drop_column("voter_participation", "state")
    op.execute("DROP TYPE IF EXISTS participation_state")
    op.alter_column("voter_participation", "account_id", nullable=False)
    op.create_primary_key("pk_voter_participation", "voter_participation", ["account_id", "election_id"])
    op.create_foreign_key(
        "fk_voter_participation_account_id_accounts", "voter_participation", "accounts", ["account_id"], ["id"]
    )
