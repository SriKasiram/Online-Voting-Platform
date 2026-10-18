"""Database engine and the per-request session used by the routers."""

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings

engine = create_engine(settings.database_url(), pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, closed when the request ends."""
    with SessionLocal() as session:
        yield session


DbSession = Annotated[Session, Depends(get_db)]
