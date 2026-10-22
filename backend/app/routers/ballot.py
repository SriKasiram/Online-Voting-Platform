"""
The ballot: give a signed-in voter their division's ballot paper, then accept it once.

SR-03: one ballot per elector per election. Issuing a ballot marks the
elector "issued" and creates a single-use token that expires
BALLOT_TOKEN_MINUTES later. Accepting it locks the elector's row, then the
token row, consumes the token, stores the ballot and marks the elector
"voted", all in one transaction: a token is never used without a ballot, and
a ballot never exists without the elector marked as voted.

Ballot secrecy: the ballot row stores no voter, no token, no reference and no
time. The token row stores no voter. Participation stores no time.
"""

import json
import secrets
from datetime import timedelta
from typing import Any, NoReturn

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

# SR-07: ballot papers come only from the verified, signed definition
from app.ballot_definitions import verified_division
from app.config import settings
# SR-05: both voting routes take CurrentElector, so staff accounts get 403 here
from app.deps import CurrentElector, CurrentSession, DbSession
from app.eligibility import eligible_division
from app.models import (
    Account,
    AuthSession,
    Ballot,
    BallotToken,
    Election,
    ElectionStatus,
    ParticipationState,
    VoterParticipation,
)
from app.schemas import BallotOut, CandidateOut, SubmitIn, SubmitOut
from app.security import audit, hash_token, new_token, utc_now

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


def definition_entry(db: Session, voter: Account, election: Election, division_id: int) -> dict[str, Any]:
    """
    SR-07: the elector's ballot paper, taken only from the election's active
    definition after verifying it, never from the candidates table. Without a
    verified definition nothing is served (fail closed): anything this request
    changed is undone, the problem is audited and the answer is 503.
    """
    entry, reason = verified_division(db, election, division_id)
    if entry is None:
        db.rollback()
        log(db, "BALLOT_DEFINITION_INVALID", voter, reason=reason)
        db.commit()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "ballot_unavailable")
    return entry


def receipt_code() -> str:
    """
    Random, so it confirms acceptance without revealing the vote.
    SR-03: stored only on the used token row, and never derived from the ballot.
    """
    chars = "".join(secrets.choice(RECEIPT_ALPHABET) for _ in range(8))
    return f"{chars[:4]}-{chars[4:]}"


def token_hash(token: str) -> str:
    # SR-03: the SHA-256 of the token, as hex, is all that is ever stored
    return hash_token(token).hex()


def log(db: Session, event_type: str, voter: Account, **details: str) -> None:
    # SR-03: names the account and the event only, never a token, reference or ballot content
    audit(db, event_type, actor=f"account:{voter.id}", **details)


def reject(db: Session, voter: Account, reason: str, status_code: int, detail: str) -> NoReturn:
    # SR-03: undoes everything and releases the row locks, then records why. The answer stays generic.
    db.rollback()
    log(db, "BALLOT_TOKEN_REJECTED", voter, reason=reason)
    db.commit()
    raise HTTPException(status_code, detail)


def end_session_soon(db: Session, session_hash: bytes) -> None:
    # SR-04: after an accepted ballot the session lasts at most POST_BALLOT_SESSION_SECONDS more,
    # enough for a safe retry and the receipt. It is never lengthened and cannot be extended.
    db.execute(
        update(AuthSession)
        .where(AuthSession.session_id_hash == session_hash)
        .values(
            expires_at=func.least(
                AuthSession.expires_at, utc_now() + timedelta(seconds=settings.post_ballot_session_seconds)
            ),
            extensions=settings.max_session_extensions,
        )
        .execution_options(synchronize_session=False)
    )


def replay(db: Session, voter: Account, receipt_reference: str, session_hash: bytes) -> SubmitOut:
    # SR-03: a used token gets the first answer again, and nothing else changes
    db.rollback()
    # SR-04: except that a safe retry also ends the session soon, as acceptance did
    end_session_soon(db, session_hash)
    log(db, "BALLOT_REPLAY_BLOCKED", voter)
    db.commit()
    return SubmitOut(receipt_id=receipt_reference)


@router.get("")
def get_ballot(voter: CurrentElector, db: DbSession) -> BallotOut:
    """The ballot paper for the voter's division, with a one-time token to submit it."""
    election = open_election(db)
    # SR-02: eligibility from the signed roll record, before any ballot token exists. The division
    # comes only from that record; any division the browser sends is never read.
    division_id = eligible_division(db, voter, election)
    # SR-03: one participation row per elector per election. If it already exists, the elector
    # has a token or has voted, so nothing more is issued.
    issued = db.execute(
        insert(VoterParticipation)
        .values(roll_id=voter.roll_id, election_id=election.id, state=ParticipationState.ISSUED)
        .on_conflict_do_nothing()
        .returning(VoterParticipation.roll_id)
    ).first()
    if issued is None:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "already_voted")

    # SR-07: the paper comes from the verified definition, in the same response shape as before
    entry = definition_entry(db, voter, election, division_id)
    # SR-03: 256 random bits, returned once. Only its hash and expiry are stored, never who received it.
    token = new_token()
    ballot = BallotOut(
        ballot_token=token,
        election_name=election.name,
        division_name=entry["name"],
        state_name=entry["state"],
        candidates=[
            CandidateOut(id=c["candidate_id"], given_name=c["given_name"], surname=c["surname"], party=c["party"])
            for c in entry["candidates"]
        ],
    )
    db.add(
        BallotToken(
            election_id=election.id,
            token_hash=token_hash(token),
            expires_at=utc_now() + timedelta(minutes=settings.ballot_token_minutes),
        )
    )
    log(db, "BALLOT_TOKEN_ISSUED", voter)
    db.commit()
    return ballot


@router.post("/submit")
def submit_ballot(body: SubmitIn, voter: CurrentElector, session: CurrentSession, db: DbSession) -> SubmitOut:
    """Accepts a full preferential ballot once per voter."""
    # SR-04: the same session CurrentElector checked, kept here so acceptance can end it
    session_hash = session.session_id_hash
    election = open_election(db)
    # SR-02: checked again before the vote is accepted, and the division comes from the signed record
    division_id = eligible_division(db, voter, election)

    # SR-03 (a): lock the elector's participation row first, then the token row, always in that order
    participation = db.scalars(
        select(VoterParticipation)
        .where(VoterParticipation.roll_id == voter.roll_id, VoterParticipation.election_id == election.id)
        .with_for_update()
    ).first()
    if participation is None:
        reject(db, voter, "wrong_state", status.HTTP_400_BAD_REQUEST, "invalid_ballot")
    # SR-03 (b): unknown or altered tokens change nothing
    digest = token_hash(body.ballot_token)
    token = db.scalars(
        select(BallotToken)
        .where(BallotToken.token_hash == digest, BallotToken.election_id == election.id)
        .with_for_update()
    ).first()
    if token is None:
        reject(db, voter, "invalid", status.HTTP_400_BAD_REQUEST, "invalid_ballot")
    # SR-03 (c): already used: the same answer as the first time, and no second ballot
    if token.consumed_at is not None:
        return replay(db, voter, token.receipt_reference or "", session_hash)
    # SR-03 (d): expired BALLOT_TOKEN_MINUTES after it was issued
    now = utc_now()
    if token.expires_at <= now:
        reject(db, voter, "expired", status.HTTP_400_BAD_REQUEST, "ballot_expired")
    # SR-03 (e): only an elector whose ballot is issued, not yet voted, can use a token
    if participation.state != ParticipationState.ISSUED:
        reject(db, voter, "wrong_state", status.HTTP_409_CONFLICT, "already_voted")

    # Every candidate numbered exactly once. The frontend checks this too, but only this check counts.
    # SR-07: "every candidate" means the candidates of this division in the verified definition
    expected = {c["candidate_id"] for c in definition_entry(db, voter, election, division_id)["candidates"]}
    ranking = body.ranked_candidate_ids
    if len(ranking) != len(expected) or set(ranking) != expected:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid_ballot")

    # SR-03 (g): consume the token with one conditional UPDATE. Exactly one row must change.
    receipt = receipt_code()
    consumed = db.execute(
        update(BallotToken)
        .where(BallotToken.token_hash == digest, BallotToken.consumed_at.is_(None), BallotToken.expires_at > now)
        .values(consumed_at=now, receipt_reference=receipt)
        .execution_options(synchronize_session=False)
    ).rowcount
    if consumed != 1:
        db.rollback()
        again = db.scalars(select(BallotToken).where(BallotToken.token_hash == digest)).one()
        if again.consumed_at is None:
            reject(db, voter, "expired", status.HTTP_400_BAD_REQUEST, "ballot_expired")
        return replay(db, voter, again.receipt_reference or "", session_hash)

    # SR-03 (h): store the ballot with no voter, token, reference or time, and mark the elector
    # voted, in the same transaction. Stage 2 keeps the preferences as plain JSON in the
    # ciphertext column; a later stage encrypts them.
    db.add(
        Ballot(
            election_id=election.id,
            division_id=division_id,
            ciphertext=json.dumps(ranking).encode(),
            nonce=b"",
            key_id="unencrypted",
        )
    )
    db.execute(
        update(VoterParticipation)
        .where(VoterParticipation.roll_id == voter.roll_id, VoterParticipation.election_id == election.id)
        .values(state=ParticipationState.VOTED)
        .execution_options(synchronize_session=False)
    )
    # SR-04: in the same transaction, the session now ends within POST_BALLOT_SESSION_SECONDS
    end_session_soon(db, session_hash)
    log(db, "BALLOT_ACCEPTED", voter)
    db.commit()
    return SubmitOut(receipt_id=receipt)
