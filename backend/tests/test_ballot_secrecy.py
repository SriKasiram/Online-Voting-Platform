"""
Ballot secrecy, checked against the migrated database.

ballots and ballot_tokens may hold only the columns listed here. A new column
fails these tests on purpose, so whoever adds one has to stop and confirm it
cannot identify a voter.
"""

import pytest
from sqlalchemy import Engine, inspect

EXPECTED_COLUMNS = {
    # SR-03: the rebuilt token table. No elector, no division and no issue time.
    # SR-12: and no expiry or "used at" time either
    "ballot_tokens": {"id", "election_id", "token_hash", "receipt_reference"},
    # SR-11: the division and the ranking exist only inside the AES-256-GCM encrypted payload
    "ballots": {"id", "election_id", "encrypted_payload"},
}
ANONYMOUS_TABLES = sorted(EXPECTED_COLUMNS)

# SR-12: an anonymous row points to no table at all (elections are identity-side, app/stores.py)
ALLOWED_REFERENCES: set[str] = set()

# SR-12: no time of any kind on the ballot side (SR-03 used to allow a token's expiry and use time)
ALLOWED_TIME_COLUMNS: dict[str, set[str]] = {"ballot_tokens": set(), "ballots": set()}


@pytest.mark.parametrize("table", ANONYMOUS_TABLES)
def test_only_the_expected_columns_exist(engine: Engine, table: str) -> None:
    columns = {column["name"] for column in inspect(engine).get_columns(table)}

    assert columns == EXPECTED_COLUMNS[table]


@pytest.mark.parametrize("table", ANONYMOUS_TABLES)
def test_no_reference_to_accounts_or_the_roll(engine: Engine, table: str) -> None:
    referenced = {fk["referred_table"] for fk in inspect(engine).get_foreign_keys(table)}

    assert referenced <= ALLOWED_REFERENCES


@pytest.mark.parametrize("table", ANONYMOUS_TABLES)
def test_no_date_or_time_columns(engine: Engine, table: str) -> None:
    """SR-03, SR-12: neither ballots nor tokens hold any date or time."""
    for column in inspect(engine).get_columns(table):
        sql_type = column["type"].compile(dialect=engine.dialect).upper()
        if column["name"] in ALLOWED_TIME_COLUMNS[table]:
            continue
        assert not any(word in sql_type for word in ("DATE", "TIME", "INTERVAL")), (
            f"{table}.{column['name']} has type {sql_type}"
        )
