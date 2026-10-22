"""SR-07: signed, versioned ballot definitions.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-22

The old ballot_definitions table (0001: one unsigned JSON row per division,
which nothing read) is replaced by one signed payload per election and
version. Only one version per election may be active. Its old rows are seed
data only and are dropped; run python -m scripts.seed to sign and activate
version 1 for the seeded election.

elections.starts_at and ends_at already are the times polls open and close
(the open-election check uses them), so no columns are added there.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SR-07: the unsigned per-division rows go; signed versions per election replace them
    op.drop_table("ballot_definitions")
    op.create_table(
        "ballot_definitions",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("election_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("signatures", postgresql.JSONB(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["election_id"], ["elections.id"], name=op.f("fk_ballot_definitions_election_id_elections")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ballot_definitions")),
        sa.UniqueConstraint("election_id", "version", name=op.f("uq_ballot_definitions_election_id_version")),
    )
    # SR-07: at most one active version per election
    op.create_index(
        "uq_ballot_definitions_one_active",
        "ballot_definitions",
        ["election_id"],
        unique=True,
        postgresql_where=sa.text("is_active"),
    )


def downgrade() -> None:
    # SR-07: back to the 0001 table, empty. Signed versions cannot be represented there.
    op.drop_index("uq_ballot_definitions_one_active", table_name="ballot_definitions")
    op.drop_table("ballot_definitions")
    op.create_table(
        "ballot_definitions",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("election_id", sa.Uuid(), nullable=False),
        sa.Column("division_id", sa.Integer(), nullable=False),
        sa.Column("definition", postgresql.JSONB(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=True),
        sa.ForeignKeyConstraint(
            ["election_id"], ["elections.id"], name=op.f("fk_ballot_definitions_election_id_elections")
        ),
        sa.ForeignKeyConstraint(
            ["division_id"], ["divisions.id"], name=op.f("fk_ballot_definitions_division_id_divisions")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ballot_definitions")),
        sa.UniqueConstraint(
            "election_id", "division_id", name=op.f("uq_ballot_definitions_election_id_division_id")
        ),
    )
