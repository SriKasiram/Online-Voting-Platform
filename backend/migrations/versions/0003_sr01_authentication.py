"""SR-01: sign-in stages on sessions, and the last accepted authenticator time step.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-21

accounts.failed_logins and accounts.locked_until already exist (0001) and are
now used for the lockout. A sign in waiting for its code becomes a session at
stage mfa_pending, which replaces the login_challenges table.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SR-01: a code's time step is stored once accepted, so the same code cannot sign in twice
    op.add_column("accounts", sa.Column("totp_last_step", sa.BigInteger(), nullable=True))

    # SR-01: every existing session passed both steps, so it starts as authenticated
    op.execute("CREATE TYPE session_stage AS ENUM ('mfa_pending', 'authenticated')")
    op.add_column(
        "sessions",
        sa.Column(
            "stage",
            postgresql.ENUM("mfa_pending", "authenticated", name="session_stage", create_type=False),
            server_default="authenticated",
            nullable=False,
        ),
    )
    op.alter_column("sessions", "stage", server_default=None)

    # SR-01: replaced by sessions at stage mfa_pending
    op.drop_table("login_challenges")


def downgrade() -> None:
    # SR-01: restores the table exactly as 0001 created it. Sign ins in progress are not carried over.
    op.create_table(
        "login_challenges",
        sa.Column("challenge_id_hash", sa.LargeBinary(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["account_id"], ["accounts.id"], name=op.f("fk_login_challenges_account_id_accounts")
        ),
        sa.PrimaryKeyConstraint("challenge_id_hash", name=op.f("pk_login_challenges")),
    )
    # SR-01: without the stage column a pending session would pass for a signed-in one, so remove them first
    op.execute("DELETE FROM sessions WHERE stage = 'mfa_pending'")
    op.drop_column("sessions", "stage")
    op.execute("DROP TYPE IF EXISTS session_stage")
    op.drop_column("accounts", "totp_last_step")
