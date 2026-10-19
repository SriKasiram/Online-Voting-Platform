"""Every model, imported here so Base.metadata knows all tables. Alembic relies on this."""

from app.models.audit import AuditLogEntry
from app.models.ballot_box import Ballot, BallotToken
from app.models.base import Base
from app.models.election import BallotDefinition, Candidate, Division, Election, ElectionStatus
from app.models.identity import (
    Account,
    AccountRole,
    AuthSession,
    ElectoralRollEntry,
    LoginChallenge,
    VoterParticipation,
)

__all__ = [
    "Account",
    "AccountRole",
    "AuditLogEntry",
    "AuthSession",
    "Ballot",
    "BallotDefinition",
    "BallotToken",
    "Base",
    "Candidate",
    "Division",
    "Election",
    "ElectionStatus",
    "ElectoralRollEntry",
    "LoginChallenge",
    "VoterParticipation",
]
