"""
SR-19: what GET /api/health checks, cheaply enough to run every 30 seconds.

The platform is available to electors only if the database answers and the keys the app needs to
serve and accept ballots are in place. Neither check re-verifies the roll or the ballot definition
(that happens at start-up, SR-02 and SR-07): a probe must stay quick and must not load the server.
"""

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ballot_crypto import BallotKeyError, load_key
from app.ballot_definitions import load_keyring
from app.config import settings
from app.roll_signing import public_key

# SR-19: a database slower than this is as good as down to an elector waiting on a ballot
STATEMENT_TIMEOUT = "2s"
HEALTH_QUERY = "SELECT 1"


def database_answers(db: Session) -> bool:
    """SR-19: the database runs a trivial query within the time limit. Never raises."""
    try:
        # SET LOCAL lasts only for this transaction, which is rolled back below
        db.execute(text(f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'"))
        db.execute(text(HEALTH_QUERY))
    except SQLAlchemyError:
        return False
    finally:
        try:
            db.rollback()
        except SQLAlchemyError:
            pass
    return True


def required_keys_loaded() -> bool:
    """
    SR-19: the keys the API already needs: the SR-11 ballot key (read from its file, because every
    ballot stored needs it), and the SR-02 roll key and SR-07 delegate keyring, which are cached
    once loaded, so these calls cost nothing after the first. Never raises.
    """
    try:
        load_key(settings.ballot_key_file)
        public_key()
        load_keyring(settings.delegate_keyring_path)
    except (BallotKeyError, OSError, ValueError, KeyError, TypeError, AttributeError):
        return False
    return True
