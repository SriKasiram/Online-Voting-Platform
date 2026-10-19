"""
Runs migrations against the database configured in app.config.

The tests pass in their own connection through config.attributes["connection"],
so they can migrate a separate test database.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, create_engine

from app.config import settings
from app.models import Base

config = context.config
target_metadata = Base.metadata

# Set up logging for command-line runs only, so pytest's logging is left alone
if config.config_file_name is not None and "connection" not in config.attributes:
    fileConfig(config.config_file_name)


def run_migrations_offline() -> None:
    """Writes the SQL to stdout instead of running it (alembic upgrade head --sql)."""
    context.configure(
        url=settings.database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_with(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        run_with(connection)
        return

    engine = create_engine(settings.database_url())
    try:
        with engine.connect() as connection:
            run_with(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
