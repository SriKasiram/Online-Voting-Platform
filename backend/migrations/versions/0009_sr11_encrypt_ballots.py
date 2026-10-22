"""SR-11: ballots encrypted at rest with AES-256-GCM.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-23

The readable ballot columns go (division_id, and ciphertext, which held the
ranking as plain JSON, with its empty nonce and key_id). One BYTEA column,
encrypted_payload, replaces them: see app/ballot_crypto.py for the format.

Assumption: the prototype database contains only seed and test data; old
plaintext test ballots are discarded and must be recreated by re-running the
seed script and casting new test ballots.

To keep the database consistent, the rows that only exist because of those
ballots go too: used ballot tokens (they hold the receipt codes) and
participation rows marked "voted", so those electors can vote again. Issued but
unused tokens, "issued" participation rows, electors, the roll, elections,
ballot definitions, staff and the audit log are kept.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # SR-11: plaintext test ballots cannot be encrypted without guessing their row binding, so they
    # are discarded, with the receipts and "voted" marks that belonged to them
    op.execute("DELETE FROM ballots")
    op.execute("DELETE FROM ballot_tokens WHERE consumed_at IS NOT NULL")
    op.execute("DELETE FROM voter_participation WHERE state = 'voted'")

    op.drop_constraint(op.f("fk_ballots_division_id_divisions"), "ballots", type_="foreignkey")
    for column in ("division_id", "ciphertext", "nonce", "key_id"):
        op.drop_column("ballots", column)
    # SR-11: version byte, nonce, ciphertext and tag in one column; the table is empty, so NOT NULL is safe
    op.add_column("ballots", sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False))


def downgrade() -> None:
    # SR-11: encrypted ballots cannot be turned back into plaintext columns without the key, and the
    # plaintext ones were discarded on upgrade, so only an empty ballots table can go back
    stored = op.get_bind().scalar(sa.text("SELECT count(*) FROM ballots"))
    if stored:
        raise RuntimeError(
            f"{stored} encrypted ballot(s) exist. SR-11 encryption cannot be reversed without the key, and the "
            "plaintext data was discarded. Delete the ballots first (python -m scripts.seed --reset), then run "
            "the downgrade again."
        )
    op.drop_column("ballots", "encrypted_payload")
    op.add_column("ballots", sa.Column("division_id", sa.Integer(), nullable=False))
    op.add_column("ballots", sa.Column("ciphertext", sa.LargeBinary(), nullable=False))
    op.add_column("ballots", sa.Column("nonce", sa.LargeBinary(), nullable=False))
    op.add_column("ballots", sa.Column("key_id", sa.Text(), nullable=False))
    op.create_foreign_key(
        op.f("fk_ballots_division_id_divisions"), "ballots", "divisions", ["division_id"], ["id"]
    )
