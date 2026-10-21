"""The database itself stops a voter being marked as voted twice in one election."""

import pytest
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Account, AccountRole, Election, VoterParticipation


def test_second_mark_for_the_same_voter_and_election_is_rejected(db_session: Session) -> None:
    election = db_session.scalars(select(Election)).one()
    first, second = db_session.scalars(
        select(Account).where(Account.role == AccountRole.VOTER).order_by(Account.username).limit(2)
    ).all()

    # Plain INSERT statements, so the check is the database constraint
    # and not SQLAlchemy's own bookkeeping
    mark = insert(VoterParticipation)
    db_session.execute(mark.values(account_id=first.id, election_id=election.id))
    # A different voter in the same election is fine
    db_session.execute(mark.values(account_id=second.id, election_id=election.id))

    with pytest.raises(IntegrityError):
        db_session.execute(mark.values(account_id=first.id, election_id=election.id))
