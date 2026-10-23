"""SR-18: an optional release version on audit entries.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-23

audit_log gains version, an optional whole number filled only by the result release events
(RESULT_RELEASED, RESULT_RELEASE_REFUSED). New rows are written with format_version 3, whose hash
also covers version. No existing row is touched, so format 1 and 2 rows keep verifying with their
own formulas (app/security.py). The v2_fields check constraint already applies to every format
other than 1, so it covers version 3 rows as well.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SR-18: a new column only; the append-only trigger stays, and no row is rewritten
    op.add_column("audit_log", sa.Column("version", sa.Integer(), nullable=True))


def downgrade() -> None:
    # Format 3 rows would no longer verify without this column. Downgrade only test data.
    op.drop_column("audit_log", "version")
