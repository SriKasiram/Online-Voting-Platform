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
    "ballot_tokens": {"id", "election_id", "token_hash", "expires_at", "consumed_at", "receipt_reference"},
    "ballots": {"id", "election_id", "division_id", "ciphertext", "nonce", "key_id"},
}
ANONYMOUS_TABLES = sorted(EXPECTED_COLUMNS)

# The only tables an anonymous row may point to
ALLOWED_REFERENCES = {"elections", "divisions"}

# SR-03: a token has to expire and record when it was used. Nothing else may hold a time.
ALLOWED_TIME_COLUMNS = {"ballot_tokens": {"expires_at", "consumed_at"}, "ballots": set()}


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
    """SR-03: ballots hold no time at all, and tokens only their expiry and when they were used."""
    for column in inspect(engine).get_columns(table):
        sql_type = column["type"].compile(dialect=engine.dialect).upper()
        if column["name"] in ALLOWED_TIME_COLUMNS[table]:
            continue
        assert not any(word in sql_type for word in ("DATE", "TIME", "INTERVAL")), (
            f"{table}.{column['name']} has type {sql_type}"
        )
