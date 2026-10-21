"""SR-02: signed electoral roll records, records without a division, and each election's polling date.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-22

The date of birth is already on the roll (electoral_roll.date_of_birth_enc,
encrypted, since 0002), so no new column is needed for it.

Existing roll records have no signature after this migration, and the API
refuses to start until they are signed. Run python -m scripts.sign_roll (or
python -m scripts.seed, which signs too) before starting the API.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SR-02: Ed25519 signature over each record's eligibility fields. Empty until the roll is signed.
    op.add_column("electoral_roll", sa.Column("record_signature", sa.LargeBinary(), nullable=True))
    # SR-02: an elector may have no division assigned, and is then refused a ballot
    op.alter_column("electoral_roll", "division_id", existing_type=sa.Integer(), nullable=True)
    # SR-02: age is worked out on polling day. Existing elections take the day they close (UTC).
    op.add_column("elections", sa.Column("polling_date", sa.Date(), nullable=True))
    op.execute("UPDATE elections SET polling_date = (ends_at AT TIME ZONE 'UTC')::date")
    op.alter_column("elections", "polling_date", existing_type=sa.Date(), nullable=False)


def downgrade() -> None:
    op.drop_column("elections", "polling_date")
    # SR-02: fails if a record has no division, rather than inventing one for it
    op.alter_column("electoral_roll", "division_id", existing_type=sa.Integer(), nullable=False)
    op.drop_column("electoral_roll", "record_signature")
