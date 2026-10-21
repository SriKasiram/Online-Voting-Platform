"""The Alembic migrations build exactly what the SQLAlchemy models describe."""

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine


def test_models_match_the_migrations(engine: Engine, alembic_config: Config) -> None:
    with engine.connect() as connection:
        alembic_config.attributes["connection"] = connection
        # Raises if someone changed a model without writing a migration
        command.check(alembic_config)
