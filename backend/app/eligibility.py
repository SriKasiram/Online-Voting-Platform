"""
SR-02: whether a signed-in voter may have a ballot, decided only from their
signed roll record. Fails closed: anything missing or wrong is a denial.
"""

from datetime import date

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Account, Election, ElectoralRollEntry
from app.roll_signing import public_key, verify_record
from app.audit_events import DENIED
from app.security import account_actor, audit, decrypt_or_none


def age_on(born: date, day: date) -> int:
    """
    SR-02: whole years of age on `day`, counting one year less until that year's
    birthday is reached. Someone born on 29 February is therefore treated as
    born on 1 March in years without a 29 February: still 17 on 28 February of
    the year they turn 18, and 18 on 1 March.
    """
    return day.year - born.year - ((day.month, day.day) < (born.month, born.day))


def birth_date(entry: ElectoralRollEntry) -> date | None:
    value = decrypt_or_none(entry.date_of_birth_enc, "electoral_roll.date_of_birth")
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def eligible_division(db: Session, account: Account, election: Election) -> int:
    """
    SR-02: checks, in order, that the voter's roll record exists, its signature
    is valid, they are enrolled, they have a division, and they are at least
    MIN_VOTING_AGE on the election's polling date. Returns the division from the
    verified record. Every denial looks the same to the voter (403
    not_enrolled), so a failed signature cannot be told apart from not being
    enrolled. Only the audit entry records the reason.
    """
    roll = db.get(ElectoralRollEntry, account.roll_id) if account.roll_id else None
    if roll is None:
        reason = "no_record"
    elif not verify_record(public_key(), roll):
        reason = "bad_signature"
    elif not roll.enrolled:
        reason = "not_enrolled"
    elif roll.division_id is None:
        reason = "no_division"
    # A record with no readable date of birth cannot show the voter is old enough
    elif (born := birth_date(roll)) is None or age_on(born, election.polling_date) < settings.min_voting_age:
        reason = "under_age"
    else:
        return roll.division_id
    # SR-16: a rejection, in its own transaction; the reason is one of the SR-02 codes
    actor, role = account_actor(account)
    audit(db, "ELIGIBILITY_DENIED", outcome=DENIED, actor=actor, role=role, reason=reason)
    db.commit()
    raise HTTPException(status.HTTP_403_FORBIDDEN, "not_enrolled")
