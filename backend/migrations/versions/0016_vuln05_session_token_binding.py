"""VULN-05: a ballot token is bound to the session it was issued to.

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-26

sessions gains ballot_token_mac: an HMAC-SHA256 of the election and the ballot token, written when
the token is issued and compared in constant time on submit and replay. It is keyed with a key
derived from SECRET_KEY (HKDF, its own label), so it equals no ballot-side value, and it is on the
identity side, where sessions already are (SR-12). Nothing changes on the ballot side. Empty until a
ballot is issued in that session; a session from before this revision has none, so a token issued
before the upgrade must be issued again (an official's SR-03 reset).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("sessions", sa.Column("ballot_token_mac", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    op.drop_column("sessions", "ballot_token_mac")
