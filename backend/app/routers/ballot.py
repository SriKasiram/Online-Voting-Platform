"""
The ballot: give a signed-in voter their division's ballot paper, then accept it once.

Ballot secrecy: the ballot row stores no voter and no time. Marking the voter,
spending the one-time token and storing the ballot happen in one transaction,
so a vote is never half recorded.
"""

import json
import secrets

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.deps import CurrentVoter, DbSession
from app.eligibility import eligible_division
from app.models import Ballot, BallotToken, Candidate, Division, Election, ElectionStatus, VoterParticipation
from app.schemas import BallotOut, CandidateOut, SubmitIn, SubmitOut
from app.security import hash_token, new_token, utc_now

router = APIRouter(prefix="/ballot", tags=["ballot"])

# No 0, O, 1, I or L, so a receipt code is easy to read aloud
RECEIPT_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def open_election(db: Session) -> Election:
    now = utc_now()
    election = db.scalars(
        select(Election).where(
            Election.status == ElectionStatus.OPEN,
            Election.starts_at <= now,
            Election.ends_at > now,
        )
    ).first()
    if election is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no_open_election")
    return election


def ballot_candidates(db: Session, election: Election, division_id: int) -> list[Candidate]:
    return list(
        db.scalars(
            select(Candidate)
            .where(Candidate.election_id == election.id, Candidate.division_id == division_id)
            .order_by(Candidate.ballot_position)
        )
    )


def receipt_code() -> str:
    """
    Stage 2: random, not stored and not linked to the ballot, so it confirms
    acceptance without revealing the vote. A later stage can make it checkable.
    """
    chars = "".join(secrets.choice(RECEIPT_ALPHABET) for _ in range(8))
    return f"{chars[:4]}-{chars[4:]}"


@router.get("")
def get_ballot(voter: CurrentVoter, db: DbSession) -> BallotOut:
    """The ballot paper for the voter's division, with a one-time token to submit it."""
    election = open_election(db)
    # SR-02: eligibility from the signed roll record, before any ballot token exists. The division
    # comes only from that record; any division the browser sends is never read.
    division_id = eligible_division(db, voter, election)
    if db.get(VoterParticipation, (voter.id, election.id)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "already_voted")

    division = db.get_one(Division, division_id)
    token = new_token()
    ballot = BallotOut(
        ballot_token=token,
        election_name=election.name,
        division_name=division.name,
        state_name=division.state,
        candidates=[
            CandidateOut(id=c.id, given_name=c.given_name, surname=c.surname, party=c.party)
            for c in ballot_candidates(db, election, division.id)
        ],
    )
    # The token row records the election and division only, never who received it
    db.add(BallotToken(token_hash=hash_token(token), election_id=election.id, division_id=division.id))
    db.commit()
    return ballot


@router.post("/submit")
def submit_ballot(body: SubmitIn, voter: CurrentVoter, db: DbSession) -> SubmitOut:
    """Accepts a full preferential ballot once per voter."""
    election = open_election(db)
    # SR-02: checked again before the vote is accepted, and the division comes from the signed record
    division_id = eligible_division(db, voter, election)

    # Every candidate numbered exactly once. The frontend checks this too, but only this check counts.
    expected = {c.id for c in ballot_candidates(db, election, division_id)}
    ranking = body.ranked_candidate_ids
    if len(ranking) != len(expected) or set(ranking) != expected:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid_ballot")

    # 1. Mark the voter. The primary key (account_id, election_id) refuses a second vote.
    try:
        # SR-02: CurrentVoter is now the account itself
        db.execute(insert(VoterParticipation).values(account_id=voter.id, election_id=election.id))
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "already_voted") from None

    # 2. Spend the token. It must be unused and issued for this election and division.
    spent = db.execute(
        update(BallotToken)
        .where(
            BallotToken.token_hash == hash_token(body.ballot_token),
            BallotToken.election_id == election.id,
            BallotToken.division_id == division_id,
            BallotToken.used.is_(False),
        )
        .values(used=True)
        .returning(BallotToken.token_hash)
        .execution_options(synchronize_session=False)
    ).first()
    if spent is None:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid_ballot")

    # 3. Store the ballot with no voter and no time. Stage 2 keeps the preferences
    #    as plain JSON in the ciphertext column; a later stage encrypts them.
    db.add(
        Ballot(
            election_id=election.id,
            division_id=division_id,
            ciphertext=json.dumps(ranking).encode(),
            nonce=b"",
            key_id="unencrypted",
        )
    )
    db.commit()
    return SubmitOut(receipt_id=receipt_code())
