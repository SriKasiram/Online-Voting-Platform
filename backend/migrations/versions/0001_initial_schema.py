"""Initial schema: election setup, voter identity and sign in, anonymous ballot box and audit log.

Revision ID: 0001
Revises:
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RANDOM_UUID = sa.text("gen_random_uuid()")
NOW = sa.text("now()")


def upgrade() -> None:
    # Case-insensitive text type, used for usernames
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")

    # ---------------------------------------------------------------
    # Election setup
    # ---------------------------------------------------------------
    op.create_table(
        "elections",
        sa.Column("id", sa.Uuid(), server_default=RANDOM_UUID, nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.Enum("OPEN", "CLOSED", "TALLIED", name="election_status"),
            nullable=False,
        ),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_elections")),
    )

    op.create_table(
        "divisions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_divisions")),
        sa.UniqueConstraint("name", name=op.f("uq_divisions_name")),
    )

    op.create_table(
        "candidates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("election_id", sa.Uuid(), nullable=False),
        sa.Column("division_id", sa.Integer(), nullable=False),
        sa.Column("given_name", sa.Text(), nullable=False),
        sa.Column("surname", sa.Text(), nullable=False),
        sa.Column("party", sa.Text(), nullable=False),
        sa.Column("ballot_position", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["election_id"], ["elections.id"], name=op.f("fk_candidates_election_id_elections")
        ),
        sa.ForeignKeyConstraint(
            ["division_id"], ["divisions.id"], name=op.f("fk_candidates_division_id_divisions")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_candidates")),
        sa.UniqueConstraint(
            "election_id",
            "division_id",
            "ballot_position",
            name=op.f("uq_candidates_election_id_division_id_ballot_position"),
        ),
    )

    op.create_table(
        "ballot_definitions",
        sa.Column("id", sa.Uuid(), server_default=RANDOM_UUID, nullable=False),
        sa.Column("election_id", sa.Uuid(), nullable=False),
        sa.Column("division_id", sa.Integer(), nullable=False),
        sa.Column("definition", postgresql.JSONB(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=True),
        sa.ForeignKeyConstraint(
            ["election_id"],
            ["elections.id"],
            name=op.f("fk_ballot_definitions_election_id_elections"),
        ),
        sa.ForeignKeyConstraint(
            ["division_id"],
            ["divisions.id"],
            name=op.f("fk_ballot_definitions_division_id_divisions"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ballot_definitions")),
        sa.UniqueConstraint(
            "election_id", "division_id", name=op.f("uq_ballot_definitions_election_id_division_id")
        ),
    )

    # ---------------------------------------------------------------
    # Voter identity. Nothing here links to a ballot.
    # ---------------------------------------------------------------
    op.create_table(
        "electoral_roll",
        sa.Column("id", sa.Uuid(), server_default=RANDOM_UUID, nullable=False),
        sa.Column("roll_lookup", sa.LargeBinary(), nullable=False),
        sa.Column("full_name_enc", sa.LargeBinary(), nullable=False),
        sa.Column("address_enc", sa.LargeBinary(), nullable=False),
        sa.Column("division_id", sa.Integer(), nullable=False),
        sa.Column("enrolled", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["division_id"], ["divisions.id"], name=op.f("fk_electoral_roll_division_id_divisions")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_electoral_roll")),
        sa.UniqueConstraint("roll_lookup", name=op.f("uq_electoral_roll_roll_lookup")),
    )

    op.create_table(
        "accounts",
        sa.Column("id", sa.Uuid(), server_default=RANDOM_UUID, nullable=False),
        sa.Column("username", postgresql.CITEXT(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column(
            "role",
            sa.Enum("VOTER", "ELECTION_OFFICIAL", name="account_role"),
            nullable=False,
        ),
        sa.Column("roll_id", sa.Uuid(), nullable=True),
        sa.Column("totp_secret_enc", sa.LargeBinary(), nullable=False),
        sa.Column("failed_logins", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["roll_id"], ["electoral_roll.id"], name=op.f("fk_accounts_roll_id_electoral_roll")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_accounts")),
        sa.UniqueConstraint("username", name=op.f("uq_accounts_username")),
    )

    op.create_table(
        "sessions",
        sa.Column("session_id_hash", sa.LargeBinary(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["account_id"], ["accounts.id"], name=op.f("fk_sessions_account_id_accounts")
        ),
        sa.PrimaryKeyConstraint("session_id_hash", name=op.f("pk_sessions")),
    )

    # Sign ins that passed the password step and wait for the 6-digit code
    op.create_table(
        "login_challenges",
        sa.Column("challenge_id_hash", sa.LargeBinary(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["account_id"], ["accounts.id"], name=op.f("fk_login_challenges_account_id_accounts")
        ),
        sa.PrimaryKeyConstraint("challenge_id_hash", name=op.f("pk_login_challenges")),
    )

    op.create_table(
        "voter_participation",
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("election_id", sa.Uuid(), nullable=False),
        sa.Column("marked_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.ForeignKeyConstraint(
            ["account_id"], ["accounts.id"], name=op.f("fk_voter_participation_account_id_accounts")
        ),
        sa.ForeignKeyConstraint(
            ["election_id"],
            ["elections.id"],
            name=op.f("fk_voter_participation_election_id_elections"),
        ),
        # Doubles as UNIQUE(account_id, election_id): one vote per voter per election
        sa.PrimaryKeyConstraint("account_id", "election_id", name=op.f("pk_voter_participation")),
    )

    # ---------------------------------------------------------------
    # Anonymous ballot box. No account column and no timestamp, by design.
    # ---------------------------------------------------------------
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

    op.create_table(
        "ballots",
        sa.Column("id", sa.Uuid(), server_default=RANDOM_UUID, nullable=False),
        sa.Column("election_id", sa.Uuid(), nullable=False),
        sa.Column("division_id", sa.Integer(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("key_id", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["election_id"], ["elections.id"], name=op.f("fk_ballots_election_id_elections")
        ),
        sa.ForeignKeyConstraint(
            ["division_id"], ["divisions.id"], name=op.f("fk_ballots_division_id_divisions")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ballots")),
    )

    # ---------------------------------------------------------------
    # Audit log
    # ---------------------------------------------------------------
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=NOW, nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column(
            "details",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("prev_hash", sa.LargeBinary(), nullable=False),
        sa.Column("hash", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
        sa.UniqueConstraint("prev_hash", name=op.f("uq_audit_log_prev_hash")),
    )


def downgrade() -> None:
    for table in (
        "audit_log",
        "ballots",
        "ballot_tokens",
        "voter_participation",
        "login_challenges",
        "sessions",
        "accounts",
        "electoral_roll",
        "ballot_definitions",
        "candidates",
        "divisions",
        "elections",
    ):
        op.drop_table(table)
    op.execute("DROP TYPE IF EXISTS account_role")
    op.execute("DROP TYPE IF EXISTS election_status")
    # The citext extension stays, because other objects in the database may use it
