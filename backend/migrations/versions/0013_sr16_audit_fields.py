"""SR-16: allow-listed audit fields, a hash format version, and an append-only audit log.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-23

audit_log gains the structured fields the SR-16 writer (app/security.py audit()) fills in:
category, outcome, role, request_id, batch_no, count and reason. The free-text details column
becomes optional: rows written before SR-16 keep theirs, and new rows leave it empty.

format_version records which hash formula a row was written with. Every existing row is
version 1 (the SR-01 formula over created_at, event_type, actor and details) and is never
rewritten, so it still verifies. New rows are version 2, hashed over the structured fields.
A check constraint makes a version 2 row carry its fields and no details.

reject_audit_change() and a BEFORE UPDATE OR DELETE row trigger make audit_log append-only:
INSERT stays allowed. The SR-13 function is not reused because its message names recorded
ballots. As with SR-13, the trigger does not stop TRUNCATE (no row trigger fires), nor a
database owner or superuser, who can disable or drop it; the hash chain and the signed audit
checkpoints (scripts/audit_checkpoint.py, scripts/verify_audit.py) detect what it cannot prevent.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STRUCTURED = ("category", "outcome", "role", "request_id")


def upgrade() -> None:
    # SR-16: new columns only; no existing row is updated, so its stored hash still holds
    op.add_column("audit_log", sa.Column("category", sa.Text(), nullable=True))
    op.add_column("audit_log", sa.Column("outcome", sa.Text(), nullable=True))
    op.add_column("audit_log", sa.Column("role", sa.Text(), nullable=True))
    op.add_column("audit_log", sa.Column("request_id", sa.Uuid(), nullable=True))
    op.add_column("audit_log", sa.Column("batch_no", sa.Integer(), nullable=True))
    op.add_column("audit_log", sa.Column("count", sa.Integer(), nullable=True))
    op.add_column("audit_log", sa.Column("reason", sa.Text(), nullable=True))
    op.add_column(
        "audit_log", sa.Column("format_version", sa.SmallInteger(), server_default=sa.text("1"), nullable=False)
    )
    # SR-16: kept for the rows that have it; new rows store nothing here
    op.alter_column(
        "audit_log",
        "details",
        existing_type=postgresql.JSONB(),
        nullable=True,
        server_default=None,
        existing_server_default=sa.text("'{}'::jsonb"),
    )
    filled = " AND ".join(f"{column} IS NOT NULL" for column in STRUCTURED)
    op.create_check_constraint(
        op.f("ck_audit_log_v2_fields"), "audit_log", f"format_version = 1 OR ({filled} AND details IS NULL)"
    )

    # SR-16: audit entries can be added, never changed or removed. No bypass flag.
    op.execute(
        """
        CREATE FUNCTION reject_audit_change() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION '% on % is not allowed: the audit log is append-only (SR-16)', TG_OP, TG_TABLE_NAME;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log "
        "FOR EACH ROW EXECUTE FUNCTION reject_audit_change()"
    )


def downgrade() -> None:
    # Version 2 rows lose their fields, so they would no longer verify. Downgrade only test data.
    op.execute("DROP TRIGGER audit_log_append_only ON audit_log")
    op.execute("DROP FUNCTION reject_audit_change()")
    op.drop_constraint(op.f("ck_audit_log_v2_fields"), "audit_log", type_="check")
    op.execute("UPDATE audit_log SET details = '{}'::jsonb WHERE details IS NULL")
    op.alter_column(
        "audit_log",
        "details",
        existing_type=postgresql.JSONB(),
        nullable=False,
        server_default=sa.text("'{}'::jsonb"),
    )
    for column in ("format_version", "reason", "count", "batch_no", "request_id", "role", "outcome", "category"):
        op.drop_column("audit_log", column)
