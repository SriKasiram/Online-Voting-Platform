"""
VULN-06: step 2 of registration answered username_taken as often as asked, so one registration
session could test any number of usernames and list the platform's accounts. The fix: at most
MAX_USERNAME_ATTEMPTS (default 5) taken usernames per registration session, each still answered
helpfully; the next one ends the session with the generic registration_session_invalid. The SR-01
sign-in lockout is unchanged.
"""

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from helpers import last_id
from app.config import settings
from app.models import AuditLogEntry, RegistrationSession

VERIFY = "/api/register/verify"
ACCOUNT = "/api/register/account"
PASSWORD = "a long enough password"


def taken_usernames(make_voter, how_many: int) -> list[str]:
    return [make_voter().username for _ in range(how_many)]


def choose(client: TestClient, username: str):
    return client.post(ACCOUNT, json={"username": username, "password": PASSWORD})


def registrations(db: Session) -> int:
    db.expire_all()
    return len(db.scalars(select(RegistrationSession)).all())


def test_a_registration_session_may_try_only_five_taken_usernames(
    client: TestClient, db_session: Session, make_person, make_voter
) -> None:
    """VULN-06 attack: the sixth taken username ends the registration with the generic answer."""
    names = taken_usernames(make_voter, 6)
    assert client.post(VERIFY, json=make_person().verify_body()).status_code == 204
    before = last_id(db_session)

    answers = [choose(client, name) for name in names]

    assert [(a.status_code, a.json()) for a in answers[:5]] == [(409, {"detail": "username_taken"})] * 5
    assert (answers[5].status_code, answers[5].json()) == (401, {"detail": "registration_session_invalid"})
    assert registrations(db_session) == 0
    # the session is gone: even a free username is now refused the same way
    assert (choose(client, "free.name").status_code, registrations(db_session)) == (401, 0)
    ended = db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.id > before)).all()
    assert [(e.event_type, e.reason, e.actor) for e in ended] == [("REGISTRATION_FAILED", "too_many_attempts", "unknown")]


def test_the_limit_is_a_setting(client: TestClient, db_session: Session, make_person, make_voter, monkeypatch) -> None:
    """VULN-06: MAX_USERNAME_ATTEMPTS=2 allows two helpful answers, then ends the session."""
    monkeypatch.setattr(settings, "max_username_attempts", 2)
    names = taken_usernames(make_voter, 3)
    client.post(VERIFY, json=make_person().verify_body())

    assert [choose(client, name).status_code for name in names] == [409, 409, 401]
    assert registrations(db_session) == 0


def test_a_free_username_within_the_limit_still_registers(client: TestClient, db_session: Session, make_person, make_voter) -> None:
    """VULN-06: four taken names, then a free one: the account step carries on as before."""
    names = taken_usernames(make_voter, 4)
    client.post(VERIFY, json=make_person().verify_body())

    assert [choose(client, name).status_code for name in names] == [409] * 4
    assert choose(client, "free.name").status_code == 200


def test_each_registration_session_has_its_own_count(client: TestClient, db_session: Session, make_person, make_voter) -> None:
    """VULN-06: the count belongs to the registration session; a new one (a new enrolment code) starts at zero."""
    names = taken_usernames(make_voter, 5)
    client.post(VERIFY, json=make_person().verify_body())
    assert [choose(client, name).status_code for name in names] == [409] * 5
    client.cookies.clear()
    client.post(VERIFY, json=make_person().verify_body())

    assert choose(client, names[0]).status_code == 409
