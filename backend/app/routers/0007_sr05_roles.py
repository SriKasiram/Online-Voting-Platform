"""SR-05: account roles for role-based access control.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-22

accounts.role changes from the account_role enum (VOTER, ELECTION_OFFICIAL)
to text limited to elector, polling_official and auditor, defaulting to
elector. Existing accounts become electors. Staff have no roll entry and
electors always have one, enforced by a CHECK. roll_id stays UNIQUE.

The upgrade refuses to run if an old ELECTION_OFFICIAL account (or any account
without a roll entry) exists, rather than turn it into staff with permissions
it never had. No such accounts are created by this project.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLE_VALID = "role IN ('elector', 'polling_official', 'auditor')"
ROLE_ROLL = "(role = 'elector' AND roll_id IS NOT NULL) OR (role <> 'elector' AND roll_id IS NULL)"


def upgrade() -> None:
    # SR-05: fail closed rather than grant staff permissions to an old account
    leftover = op.get_bind().scalar(sa.text("SELECT count(*) FROM accounts WHERE role <> 'VOTER' OR roll_id IS NULL"))
    if leftover:
        raise RuntimeError(
            f"{leftover} account(s) are not voters with a roll entry. Delete or fix them, then run the upgrade again."
        )
    # SR-05: every existing account is a voter on the roll, so it becomes an elector
    op.alter_column(
        "accounts",
        "role",
        type_=sa.String(20),
        existing_type=postgresql.ENUM(name="account_role", create_type=False),
        postgresql_using="'elector'",
    )
    op.alter_column("accounts", "role", server_default="elector")
    op.execute("DROP TYPE account_role")
    op.create_check_constraint(op.f("ck_accounts_role_valid"), "accounts", ROLE_VALID)
    op.create_check_constraint(op.f("ck_accounts_role_roll"), "accounts", ROLE_ROLL)


def downgrade() -> None:
    # SR-05: the old enum cannot tell a polling official from an auditor, and an upgrade would refuse
    # what it became, so refuse while staff accounts exist rather than lose or blur their roles
    staff = op.get_bind().scalar(sa.text("SELECT count(*) FROM accounts WHERE role <> 'elector'"))
    if staff:
        raise RuntimeError(f"{staff} staff account(s) exist. Delete them first, then run the downgrade again.")
    op.drop_constraint(op.f("ck_accounts_role_roll"), "accounts", type_="check")
    op.drop_constraint(op.f("ck_accounts_role_valid"), "accounts", type_="check")
    op.alter_column("accounts", "role", server_default=None)
    op.execute("CREATE TYPE account_role AS ENUM ('VOTER', 'ELECTION_OFFICIAL')")
    # SR-05: only electors are left, and they become VOTER again
    op.alter_column(
        "accounts",
        "role",
        type_=postgresql.ENUM(name="account_role", create_type=False),
        existing_type=sa.String(20),
        postgresql_using="'VOTER'::account_role",
    )
