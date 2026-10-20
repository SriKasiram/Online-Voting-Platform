"""
Shared test setup.

Each run rebuilds a separate database (POSTGRES_TEST_DB, default evoting_test)
from the Alembic migrations and loads the seed data, so every run also proves
the migration and the seed script work. PostgreSQL must be running.

Each test then runs inside one transaction that is rolled back at the end, so
a vote cast in one test never leaks into the next.
"""

import re
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.orm import Session

from app.config import BACKEND_DIR, settings
from app.database import get_db
from app.main import app
from scripts.seed import seed


def recreate_test_database(name: str) -> None:
    # Refuse to drop anything that is not clearly a throwaway test database
    if not re.fullmatch(r"[a-z][a-z0-9_]*_test", name) or name == settings.postgres_db:
        raise RuntimeError(
            f"POSTGRES_TEST_DB must end in _test and differ from POSTGRES_DB (got {name!r})"
        )
    admin = create_engine(settings.database_url("postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
            connection.execute(text(f'CREATE DATABASE "{name}"'))
    finally:
        admin.dispose()


@pytest.fixture(scope="session")
def alembic_config() -> Config:
    return Config(str(BACKEND_DIR / "alembic.ini"))


@pytest.fixture(scope="session")
def engine(alembic_config: Config) -> Iterator[Engine]:
    name = settings.postgres_test_db
    recreate_test_database(name)
    test_engine = create_engine(settings.database_url(name))

    with test_engine.begin() as connection:
        alembic_config.attributes["connection"] = connection
        command.upgrade(alembic_config, "head")
    with Session(test_engine) as session:
        seed(session)

    yield test_engine
    test_engine.dispose()


@pytest.fixture
def connection(engine: Engine) -> Iterator[Connection]:
    """One connection per test, inside a transaction that is rolled back afterwards."""
    with engine.connect() as test_connection:
        transaction = test_connection.begin()
        try:
            yield test_connection
        finally:
            transaction.rollback()


def nested_session(connection: Connection) -> Session:
    # commit() inside the app or a test only releases a savepoint, so the
    # outer transaction can still undo everything
    return Session(bind=connection, join_transaction_mode="create_savepoint")


@pytest.fixture
def db_session(connection: Connection) -> Iterator[Session]:
    """A session for reading and arranging data in a test. Sees what the API wrote."""
    with nested_session(connection) as session:
        yield session


@pytest.fixture
def client(connection: Connection) -> Iterator[TestClient]:
    """An API client whose requests use the test's transaction. Keeps cookies between requests."""

    def test_db() -> Iterator[Session]:
        with nested_session(connection) as session:
            yield session

    app.dependency_overrides[get_db] = test_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
