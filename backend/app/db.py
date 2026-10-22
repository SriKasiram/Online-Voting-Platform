"""Database engine, sessions and the declarative base every model uses."""

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, Text, create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings

# SR-12: database errors never show their SQL parameters, which for the ballot routes are ballot ids,
# token hashes and receipts. Unhandled errors end up in the server log in full.
engine = create_engine(settings.database_url(), pool_pre_ping=True, hide_parameters=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    # Fixed constraint names keep the Alembic migrations predictable and readable
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_N_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )

    type_annotation_map = {
        str: Text(),
        # Every timestamp is stored with its time zone
        datetime: DateTime(timezone=True),
        dict[str, Any]: JSONB(),
    }
