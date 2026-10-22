"""SR-12: no persistent link between the identity side and the ballot side.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-23

- ballot_tokens loses expires_at and consumed_at. Both were exact times that
  matched the audit log's BALLOT_TOKEN_ISSUED (plus 10 minutes) and
  BALLOT_ACCEPTED entries, which name the elector. A token is now unused while
  receipt_reference is empty, and is usable only while its election is open and
  the elector is signed in (SR-03, SR-04).
- ballots and ballot_tokens lose their foreign keys to elections (an
  identity-side table in app/stores.py). election_id stays as a plain value.

Assumption: the prototype database contains only seed and test data. Existing
rows are kept: a token with a receipt reference counts as used, exactly as
before; only the two time columns and the two constraints go.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SR-12: no foreign key from the ballot side to the identity side
    op.drop_constraint(op.f("fk_ballots_election_id_elections"), "ballots", type_="foreignkey")
    op.drop_constraint(op.f("fk_ballot_tokens_election_id_elections"), "ballot_tokens", type_="foreignkey")
    # SR-12: no time of day on the ballot side
    op.drop_column("ballot_tokens", "expires_at")
    op.drop_column("ballot_tokens", "consumed_at")


def downgrade() -> None:
    # The old times are gone for good, so used tokens get the downgrade time and unused tokens expire now
    op.add_column("ballot_tokens", sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "ballot_tokens",
        sa.Column("expires_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.alter_column("ballot_tokens", "expires_at", server_default=None)
    op.execute("UPDATE ballot_tokens SET consumed_at = now() WHERE receipt_reference IS NOT NULL")
    op.create_foreign_key(
        op.f("fk_ballot_tokens_election_id_elections"), "ballot_tokens", "elections", ["election_id"], ["id"]
    )
    op.create_foreign_key(op.f("fk_ballots_election_id_elections"), "ballots", "elections", ["election_id"], ["id"])
