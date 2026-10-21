"""The database itself stops a voter being marked as voted twice in one election."""

import pytest
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import VoterParticipation


def test_second_mark_for_the_same_voter_and_election_is_rejected(db_session: Session, election, make_voter) -> None:
    first, second = make_voter(), make_voter()
    election_id = election.election.id

    # Plain INSERT statements, so the check is the database constraint
    # and not SQLAlchemy's own bookkeeping
    mark = insert(VoterParticipation)
    db_session.execute(mark.values(account_id=first.account_id, election_id=election_id))
    # A different voter in the same election is fine
    db_session.execute(mark.values(account_id=second.account_id, election_id=election_id))

    with pytest.raises(IntegrityError):
        db_session.execute(mark.values(account_id=first.account_id, election_id=election_id))
