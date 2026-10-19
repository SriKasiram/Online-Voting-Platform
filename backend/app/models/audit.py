"""Append-only audit log. A later stage chains each entry to the one before it with a hash."""

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLogEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    event_type: Mapped[str]
    actor: Mapped[str]
    details: Mapped[dict[str, Any]] = mapped_column(default=dict, server_default=text("'{}'::jsonb"))
    # Placeholders until the hash chain is added. UNIQUE prev_hash stops two
    # entries from claiming the same predecessor.
    prev_hash: Mapped[bytes] = mapped_column(unique=True)
    hash: Mapped[bytes]
