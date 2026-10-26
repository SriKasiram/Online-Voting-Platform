"""VULN-06: taken usernames are counted per registration session.

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-26

registration_sessions gains username_attempts, the taken usernames tried at step 2. Past
MAX_USERNAME_ATTEMPTS the registration session is ended. It is separate from attempts (the
authenticator codes at step 3), which a race at step 3 resets.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("registration_sessions", sa.Column("username_attempts", sa.Integer(), server_default=sa.text("0"), nullable=False))


def downgrade() -> None:
    op.drop_column("registration_sessions", "username_attempts")
