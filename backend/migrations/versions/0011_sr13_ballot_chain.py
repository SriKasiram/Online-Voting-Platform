"""SR-13: an integrity-protected repository of accepted ballots.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-23

- ballot_chain: one SHA-256 hash-chain entry per sealed ballot, per election
  (app/ballot_chain.py). position and batch_no are set by the sealing script,
  never by a database sequence. ballot_id points to ballots and is unique.
  election_id is a plain value (SR-12: no link to the identity side). There is
  no time, elector, roll, session or IP column.
- reject_ballot_change() and two BEFORE UPDATE OR DELETE row triggers make
  ballots and ballot_chain append-only. INSERT stays allowed.

The triggers stop the application and ordinary SQL from changing or removing a
recorded ballot. They do not stop TRUNCATE, which fires no row trigger (the
development reset, python -m scripts.seed --reset, relies on it), nor a database
owner or superuser, who can disable or drop them. Least-privilege database roles
are design only; the hash chain and the signed checkpoints detect what the
triggers cannot prevent. The ballots table itself is not changed.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APPEND_ONLY_TABLES = ("ballots", "ballot_chain")


def upgrade() -> None:
    op.create_table(
        "ballot_chain",
        sa.Column("election_id", sa.Uuid(), nullable=False),
        # SR-13: plain integers set by the sealing code, so the database adds no order of its own
        sa.Column("position", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("batch_no", sa.Integer(), nullable=False),
        sa.Column("ballot_id", sa.Uuid(), nullable=False),
        sa.Column("prev_hash", sa.Text(), nullable=False),
        sa.Column("entry_hash", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["ballot_id"], ["ballots.id"], name=op.f("fk_ballot_chain_ballot_id_ballots")),
        sa.PrimaryKeyConstraint("election_id", "position", name=op.f("pk_ballot_chain")),
        sa.UniqueConstraint("ballot_id", name=op.f("uq_ballot_chain_ballot_id")),
    )
    # SR-13: recorded ballots and chain entries can be added, never changed or removed. No bypass
    # flag: the function refuses every UPDATE and DELETE, whoever sends it.
    op.execute(
        """
        CREATE FUNCTION reject_ballot_change() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION '% on % is not allowed: recorded ballots are append-only (SR-13)', TG_OP, TG_TABLE_NAME;
        END
        $$
        """
    )
    for table in APPEND_ONLY_TABLES:
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION reject_ballot_change()"
        )


def downgrade() -> None:
    for table in APPEND_ONLY_TABLES:
        op.execute(f"DROP TRIGGER {table}_append_only ON {table}")
    op.execute("DROP FUNCTION reject_ballot_change()")
    op.drop_table("ballot_chain")
