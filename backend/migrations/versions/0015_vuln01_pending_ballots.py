"""VULN-01, VULN-02: a holding table for accepted ballots until their seal.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-26

- pending_ballots: the same three columns as ballots (id, election_id, encrypted_payload). The
  accept transaction writes here instead of ballots (VULN-01); the SR-13 seal copies each batch into
  ballots in ballot id order and deletes it here.
- guard_pending_ballot() and a BEFORE UPDATE OR DELETE row trigger, pending_ballots_append_only:
  every UPDATE is refused, and a DELETE only once ballots holds an identical copy (same id,
  election and ciphertext), which is what the seal writes first (VULN-02). No bypass flag.
- Ballots accepted but not yet sealed move from ballots to pending_ballots, so after this revision
  ballots holds sealed ballots only. Moving them needs the SR-13 trigger on ballots off for that
  one DELETE, inside this migration's transaction.

As with SR-13 and SR-16, the trigger does not stop TRUNCATE (no row trigger fires) or a database
owner or superuser, who can disable or drop it; the VULN-02 totals check (electors marked voted =
sealed + held ballots) detects what it cannot prevent. Dead rows a move leaves in ballots keep
their old xmin on disk until a VACUUM; run VACUUM FULL ballots once after upgrading a database
that held unsealed ballots.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UNSEALED = "FROM ballots b WHERE NOT EXISTS (SELECT 1 FROM ballot_chain c WHERE c.ballot_id = b.id)"


def upgrade() -> None:
    op.create_table(
        "pending_ballots",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("election_id", sa.Uuid(), nullable=False),
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pending_ballots")),
    )
    # VULN-02: a held ballot is never changed, and leaves only once its exact copy is in ballots
    op.execute(
        """
        CREATE FUNCTION guard_pending_ballot() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' AND EXISTS (
                SELECT 1 FROM ballots b
                WHERE b.id = OLD.id AND b.election_id = OLD.election_id AND b.encrypted_payload = OLD.encrypted_payload
            ) THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION '% on % is not allowed: a held ballot leaves only through its seal (VULN-02)', TG_OP, TG_TABLE_NAME;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER pending_ballots_append_only BEFORE UPDATE OR DELETE ON pending_ballots "
        "FOR EACH ROW EXECUTE FUNCTION guard_pending_ballot()"
    )
    # VULN-01: unsealed ballots wait in the holding table, in ballot id order
    op.execute(f"INSERT INTO pending_ballots (id, election_id, encrypted_payload) SELECT b.id, b.election_id, b.encrypted_payload {UNSEALED} ORDER BY b.id")
    op.execute("ALTER TABLE ballots DISABLE TRIGGER ballots_append_only")
    op.execute(f"DELETE {UNSEALED}")
    op.execute("ALTER TABLE ballots ENABLE TRIGGER ballots_append_only")


def downgrade() -> None:
    # Held ballots go back to ballots, unsealed, as before this revision
    op.execute("INSERT INTO ballots (id, election_id, encrypted_payload) SELECT id, election_id, encrypted_payload FROM pending_ballots ORDER BY id")
    op.execute("DROP TRIGGER pending_ballots_append_only ON pending_ballots")
    op.execute("DROP FUNCTION guard_pending_ballot()")
    op.drop_table("pending_ballots")
