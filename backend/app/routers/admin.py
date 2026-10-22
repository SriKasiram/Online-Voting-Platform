"""
SR-05: administrative routes for staff. Every one is declared through
AdminRouter with a permission from app/rbac.py, so the role check runs before
the endpoint does, and an unmapped route stops the API from starting.
"""

import uuid

from fastapi import HTTPException, Query, status
from sqlalchemy import func, select

from app.deps import CurrentSession, DbSession
from app.models import AuditLogEntry, Division, Election, ElectoralRollEntry, VoterParticipation
from app.participation import reset_issued
from app.rbac import AUDIT_READ, AUDIT_VERIFY, ELECTOR_RESET, TURNOUT_READ, AdminRouter
from app.schemas import AuditEntryOut, DivisionTurnout, ResetOut, StateCounts, TurnoutOut
from app.security import verify_audit_chain

router = AdminRouter(prefix="/admin", tags=["admin"])

AUDIT_PAGE_MAX = 200


@router.get("/turnout", permission=TURNOUT_READ)
def turnout(db: DbSession) -> TurnoutOut:
    """SR-05: electors issued a ballot and electors who have voted, per division and in total, latest election."""
    election = db.scalars(select(Election).order_by(Election.starts_at.desc())).first()
    if election is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    in_election = VoterParticipation.election_id == election.id
    per_division = db.execute(
        select(ElectoralRollEntry.division_id, VoterParticipation.state, func.count())
        .join(ElectoralRollEntry, ElectoralRollEntry.id == VoterParticipation.roll_id)
        .where(in_election)
        .group_by(ElectoralRollEntry.division_id, VoterParticipation.state)
    ).all()
    counts = {division_id: {"issued": 0, "voted": 0} for division_id in db.scalars(select(Division.id))}
    for division_id, state, number in per_division:
        if division_id in counts:
            counts[division_id][state.value] += number
    totals = {"issued": 0, "voted": 0}
    for state, number in db.execute(
        select(VoterParticipation.state, func.count()).where(in_election).group_by(VoterParticipation.state)
    ):
        totals[state.value] = number
    names = dict(db.execute(select(Division.id, Division.name)).tuples().all())
    return TurnoutOut(
        election=election.name,
        divisions=[DivisionTurnout(division=names[d], **c) for d, c in sorted(counts.items(), key=lambda i: names[i[0]])],
        total=StateCounts(**totals),
    )


@router.post("/electors/{roll_id}/reset", permission=ELECTOR_RESET)
def reset_elector(roll_id: uuid.UUID, session: CurrentSession, db: DbSession) -> ResetOut:
    """SR-05: clears an elector's issued ballot (SR-03 reset). Never undoes a vote."""
    result = reset_issued(db, roll_id, actor=f"staff:{session.account_id}")
    if result == "not_found":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if result == "voted":
        raise HTTPException(status.HTTP_409_CONFLICT, "already_voted")
    return ResetOut(status="reset")


@router.get("/audit-log", permission=AUDIT_READ)
def audit_log(db: DbSession, limit: int = Query(50, ge=1), offset: int = Query(0, ge=0)) -> list[AuditEntryOut]:
    """SR-05: audit entries in order, at most 200 per request, with their hashes as stored."""
    entries = db.scalars(
        select(AuditLogEntry).order_by(AuditLogEntry.id).offset(offset).limit(min(limit, AUDIT_PAGE_MAX))
    )
    return [
        AuditEntryOut(
            id=e.id,
            created_at=e.created_at,
            actor=e.actor,
            event_type=e.event_type,
            prev_hash=e.prev_hash.hex(),
            hash=e.hash.hex(),
        )
        for e in entries
    ]


@router.get("/audit-log/verify", permission=AUDIT_VERIFY)
def verify_audit_log(db: DbSession) -> dict[str, bool | int]:
    """SR-05: recomputes the whole hash chain."""
    checked, first_bad_id = verify_audit_chain(db)
    if first_bad_id is None:
        return {"ok": True, "entries": checked}
    return {"ok": False, "first_bad_id": first_bad_id}
