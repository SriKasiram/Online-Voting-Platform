"""Declarative base shared by every model."""

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase

# Fixed constraint names keep the Alembic migrations predictable and readable
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    type_annotation_map = {
        str: Text(),
        # Every timestamp is stored with its time zone
        datetime: DateTime(timezone=True),
        dict[str, Any]: JSONB(),
    }
