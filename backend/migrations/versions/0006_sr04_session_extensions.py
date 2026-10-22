"""SR-04: count the extensions each session has used.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-22

sessions already has everything else SR-04 needs: the SHA-256 of a 256-bit
identifier (session_id_hash), the stage (0003) and a fixed expires_at.
Existing sessions start with no extensions used.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SR-04: at most MAX_SESSION_EXTENSIONS, each rotating the identifier
    op.add_column("sessions", sa.Column("extensions", sa.Integer(), server_default=sa.text("0"), nullable=False))


def downgrade() -> None:
    op.drop_column("sessions", "extensions")
