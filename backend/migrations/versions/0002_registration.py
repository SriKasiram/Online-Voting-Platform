"""Registration: voters on the roll claim an account with a one-time enrolment code.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-19

roll_lookup is now a keyed hash of the normalised given name, surname, date of
birth and postcode. Entries created before this migration have no date of
birth or postcode, so their old lookup values match nothing and they cannot be
registered. Reseed to replace them (python -m scripts.seed --reset).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_ROLL_COLUMNS = (
    "date_of_birth_enc",
    "postcode_enc",
    "enrolment_code_hash",
    "code_expires_at",
    "code_attempts",
    "registered_at",
)


def upgrade() -> None:
    op.add_column("electoral_roll", sa.Column("date_of_birth_enc", sa.LargeBinary(), nullable=True))
    op.add_column("electoral_roll", sa.Column("postcode_enc", sa.LargeBinary(), nullable=True))
    op.add_column("electoral_roll", sa.Column("enrolment_code_hash", sa.LargeBinary(), nullable=True))
    op.add_column("electoral_roll", sa.Column("code_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "electoral_roll",
        sa.Column("code_attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("electoral_roll", sa.Column("registered_at", sa.DateTime(timezone=True), nullable=True))
    # Entries that already have an account count as registered
    op.execute(
        "UPDATE electoral_roll SET registered_at = now() "
        "WHERE id IN (SELECT roll_id FROM accounts WHERE roll_id IS NOT NULL)"
    )

    # One account per person on the roll, enforced by the database
    op.create_unique_constraint(op.f("uq_accounts_roll_id"), "accounts", ["roll_id"])

    op.create_table(
        "registration_sessions",
        sa.Column("id_hash", sa.LargeBinary(), nullable=False),
        sa.Column("roll_id", sa.Uuid(), nullable=False),
        sa.Column(
            "stage",
            sa.Enum("verified", "account_pending", name="registration_stage"),
            nullable=False,
        ),
        sa.Column("username", postgresql.CITEXT(), nullable=True),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("totp_secret_enc", sa.LargeBinary(), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["roll_id"],
            ["electoral_roll.id"],
            name=op.f("fk_registration_sessions_roll_id_electoral_roll"),
        ),
        sa.PrimaryKeyConstraint("id_hash", name=op.f("pk_registration_sessions")),
    )


def downgrade() -> None:
    op.drop_table("registration_sessions")
    op.execute("DROP TYPE IF EXISTS registration_stage")
    op.drop_constraint(op.f("uq_accounts_roll_id"), "accounts", type_="unique")
    for column in NEW_ROLL_COLUMNS:
        op.drop_column("electoral_roll", column)
