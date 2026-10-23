"""
SR-05: resetting an elector's "issued" ballot, shared by the development script
(python -m scripts.seed --reset-participation) and the polling official's admin
route. Moved out of the seed script without changing what it does (SR-03).
"""

import uuid
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit_events import SUCCESS
from app.models import ParticipationState, VoterParticipation
from app.security import audit


def reset_issued(db: Session, roll_id: uuid.UUID, actor: str, role: str) -> Literal["reset", "voted", "not_found"]:
    """
    Clears the elector's "issued" participation, so a new ballot can be issued,
    and audits ELECTOR_RESET as `actor` with its `role` (SR-16: the staff account, or "script"). A "voted" elector is never reset: a cast
    ballot cannot be undone, by design. Changes and commits only on "reset".
    """
    # Locked, so a ballot being accepted at the same moment either finishes first (voted) or finds no row
    rows = db.scalars(select(VoterParticipation).where(VoterParticipation.roll_id == roll_id).with_for_update()).all()
    if not rows:
        return "not_found"
    if any(row.state == ParticipationState.VOTED for row in rows):
        db.rollback()
        return "voted"
    for row in rows:
        db.delete(row)
    # SR-16: in the same transaction as the reset: if the entry cannot be written, nothing is reset
    audit(db, "ELECTOR_RESET", outcome=SUCCESS, actor=actor, role=role)
    db.commit()
    return "reset"
