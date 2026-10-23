"""SR-14: the receipt reference is no longer stored, only its SHA-256.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-23

ballot_tokens loses receipt_reference, which held each confirmation code in
plain text. It gains:
- receipt_hash: the SHA-256 (hex) of the 128-bit reference returned to the
  client. The reference is derived from the token the client presents, so the
  server never needs to keep it.
- consumed: whether the token has been used. Until now a non-empty
  receipt_reference meant "used"; that meaning moves here, so tokens used
  before this change still count as used.

Tokens consumed before this change have no receipt_hash and cannot return a
reference on replay: a retry gets the generic invalid_ballot answer. The
prototype holds test data only, so reset the development database (python -m
scripts.seed --reset) or cast new test ballots. The ballots and ballot_chain
tables are not touched (SR-13 forbids deleting from them anyway), and the token
table stays ballot-side: no elector reference and no time column (SR-12).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("ballot_tokens", sa.Column("consumed", sa.Boolean(), server_default=sa.false(), nullable=False))
    # SR-14: keep every used token used, although its reference can no longer be confirmed
    op.execute("UPDATE ballot_tokens SET consumed = true WHERE receipt_reference IS NOT NULL")
    op.add_column("ballot_tokens", sa.Column("receipt_hash", sa.Text(), nullable=True))
    op.drop_column("ballot_tokens", "receipt_reference")


def downgrade() -> None:
    op.add_column("ballot_tokens", sa.Column("receipt_reference", sa.Text(), nullable=True))
    # SR-14: the references were never stored, so a used token gets a placeholder that still marks it
    # used for the old code; a replay of it then shows the placeholder instead of the real code
    op.execute("UPDATE ballot_tokens SET receipt_reference = 'XXXX-XXXX' WHERE consumed")
    op.drop_column("ballot_tokens", "receipt_hash")
    op.drop_column("ballot_tokens", "consumed")
