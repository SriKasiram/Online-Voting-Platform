"""
SR-05: every administrative request is checked against the signed-in
account's role, read from the database each time, using the server-side
permission map. Unmapped admin routes cannot exist, and voting routes accept
electors only.
"""

import itertools
import json
import uuid
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass

import pyotp
import pytest
from fastapi import APIRouter, FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import rbac, security
from app.main import app
from app.models import Account, AccountRole, AuditLogEntry, ParticipationState, VoterParticipation
from app.rbac import ROLE_PERMISSIONS, TURNOUT_READ, AdminRouter, check_admin_routes
from app.routers import admin
from app.security import SESSION_COOKIE, decrypt, verify_password
from scripts import create_staff as create_staff_script

ROUTES = {
    "turnout": ("GET", "/api/admin/turnout"),
    "reset": ("POST", "/api/admin/electors/{roll_id}/reset"),
    "audit_log": ("GET", "/api/admin/audit-log"),
    "verify": ("GET", "/api/admin/audit-log/verify"),
}
CALLERS = ["no session", "pending", "elector", "polling_official", "auditor"]
EXPECTED = {
    "no session": dict.fromkeys(ROUTES, 401),
    "pending": dict.fromkeys(ROUTES, 401),
    "elector": dict.fromkeys(ROUTES, 403),
    "polling_official": {"turnout": 200, "reset": 200, "audit_log": 403, "verify": 403},
    "auditor": {"turnout": 200, "reset": 403, "audit_log": 200, "verify": 200},
}
FORBIDDEN = (403, {"detail": "forbidden"})


@dataclass
class Staff:
    username: str
    password: str
    totp_secret: str
    account_id: uuid.UUID

    def code(self) -> str:
        return pyotp.TOTP(self.totp_secret).at(security.utc_now())


@pytest.fixture
def make_staff(db_session: Session) -> Callable[[str], Staff]:
    """SR-05: a staff account, made by the create_staff script's own function."""
    counter = itertools.count(1)

    def make(role: str) -> Staff:
        n = next(counter)
        username, password = f"{role}.{n}", f"staff password number {n}"
        _, secret = create_staff_script.create_staff(db_session, username, role, password)
        account_id = db_session.scalars(select(Account.id).where(Account.username == username)).one()
        return Staff(username, password, secret, account_id)

    return make


@pytest.fixture
def issued_elector(db_session: Session, election, make_person):
    """SR-05: someone on the roll who has been issued a ballot (SR-03 state "issued")."""
    person = make_person(registered=True)
    db_session.add(
        VoterParticipation(roll_id=person.roll_id, election_id=election.election.id, state=ParticipationState.ISSUED)
    )
    db_session.commit()
    return person


def call(client: TestClient, route: str, roll_id: uuid.UUID | None = None):
    method, path = ROUTES[route]
    return client.request(method, path.format(roll_id=roll_id or uuid.uuid4()))


def state(db_session: Session, roll_id: uuid.UUID) -> ParticipationState | None:
    db_session.expire_all()
    row = db_session.scalars(select(VoterParticipation).where(VoterParticipation.roll_id == roll_id)).first()
    return row.state if row else None


def audit_since(db_session: Session, before: int, *events: str) -> list[AuditLogEntry]:
    query = select(AuditLogEntry).where(AuditLogEntry.id > before).order_by(AuditLogEntry.id)
    return list(db_session.scalars(query.where(AuditLogEntry.event_type.in_(events)) if events else query))


def last_id(db_session: Session) -> int:
    return db_session.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))


# ---------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------


@pytest.mark.parametrize(("caller", "route"), [(c, r) for c in CALLERS for r in ROUTES])
def test_access_control_matrix(
    client: TestClient, db_session: Session, make_voter, make_staff, sign_in, issued_elector, caller: str, route: str
) -> None:
    """SR-05 test 1: every caller against every admin route, with exactly the statuses of the matrix."""
    if caller == "pending":
        staff = make_staff("auditor")
        client.post("/api/auth/login", json={"username": staff.username, "password": staff.password})
    elif caller == "elector":
        sign_in(make_voter())
    elif caller != "no session":
        sign_in(make_staff(caller))

    response = call(client, route, issued_elector.roll_id)

    expected = EXPECTED[caller][route]
    assert response.status_code == expected, response.text
    if expected == 401:
        assert response.json() == {"detail": "not_signed_in"}
    if expected == 403:
        assert response.json() == {"detail": "forbidden"}
    # Only an allowed reset changes anything
    reset_happened = (caller, route) == ("polling_official", "reset")
    assert state(db_session, issued_elector.roll_id) == (None if reset_happened else ParticipationState.ISSUED)


# ---------------------------------------------------------------
# Staff and the voting routes
# ---------------------------------------------------------------


def test_staff_cannot_vote_but_can_extend_and_sign_out(client: TestClient, make_staff, sign_in) -> None:
    """SR-05 test 2: the voting routes accept electors only; extension and sign out work for every role."""
    sign_in(make_staff("polling_official"))

    assert (client.get("/api/ballot").status_code, client.get("/api/ballot").json()) == FORBIDDEN
    submitted = client.post("/api/ballot/submit", json={"ballot_token": "any", "ranked_candidate_ids": [1]})
    assert (submitted.status_code, submitted.json()) == FORBIDDEN
    assert client.post("/api/auth/extend").status_code == 204
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/admin/turnout").status_code == 401


def test_staff_sign_in_end_to_end(client: TestClient, make_staff) -> None:
    """SR-05 test 3: a staff account signs in with password and code like anyone else, and sees its username."""
    staff = make_staff("auditor")

    assert client.post("/api/auth/login", json={"username": staff.username, "password": staff.password}).status_code == 204
    verified = client.post("/api/auth/verify", json={"otp_code": staff.code()})

    assert (verified.status_code, verified.json()) == (200, {"display_name": staff.username})
    assert SESSION_COOKIE in verified.cookies
    assert client.get("/api/admin/audit-log/verify").status_code == 200


def test_role_is_read_again_on_every_request(
    client: TestClient, db_session: Session, election, make_staff, sign_in
) -> None:
    """SR-05 test 4: change the role in the database and the same session is judged by the new role at once."""
    staff = make_staff("auditor")
    sign_in(staff)
    assert client.get("/api/admin/audit-log").status_code == 200

    db_session.execute(update(Account).where(Account.id == staff.account_id).values(role=AccountRole.POLLING_OFFICIAL))
    db_session.commit()

    assert (client.get("/api/admin/audit-log").status_code, client.get("/api/admin/audit-log").json()) == FORBIDDEN
    assert client.get("/api/admin/turnout").status_code == 200


def test_registration_only_ever_creates_electors(client: TestClient, db_session: Session, make_person) -> None:
    """SR-05 test 5: the normal registration flow makes an elector, even if the requests ask for another role."""
    person = make_person()
    assert client.post("/api/register/verify", json=person.verify_body() | {"role": "auditor"}).status_code == 204
    secret = client.post(
        "/api/register/account", json={"username": "new.elector", "password": "a long enough password", "role": "auditor"}
    ).json()["secret"]
    confirmed = client.post("/api/register/confirm", json={"otp_code": pyotp.TOTP(secret).now(), "role": "auditor"})

    assert confirmed.status_code == 204
    account = db_session.scalars(select(Account).where(Account.username == "new.elector")).one()
    assert (account.role, account.roll_id) == (AccountRole.ELECTOR, person.roll_id)


# ---------------------------------------------------------------
# Deny by default
# ---------------------------------------------------------------


def test_admin_routes_cannot_exist_without_a_mapped_permission() -> None:
    """SR-05 test 6: AdminRouter refuses a route with no or an unknown permission, and start-up refuses strays."""
    router = AdminRouter()

    def endpoint() -> None: ...

    with pytest.raises(TypeError):
        router.add_api_route("/x", endpoint)
    with pytest.raises(TypeError):
        router.get("/x")
    with pytest.raises(TypeError):
        router.api_route("/x", methods=["PUT"])(endpoint)
    with pytest.raises(ValueError):
        router.get("/x", permission="ballot:open")(endpoint)

    stray = FastAPI()
    stray.get("/api/admin/backdoor")(endpoint)
    with pytest.raises(RuntimeError, match="/api/admin/backdoor"):
        check_admin_routes(stray)
    # The same through an included plain router, which FastAPI keeps nested
    nested, plain = FastAPI(), APIRouter(prefix="/admin")
    plain.get("/hidden")(endpoint)
    nested.include_router(plain, prefix="/api")
    with pytest.raises(RuntimeError, match="/api/admin/hidden"):
        check_admin_routes(nested)
    # A real admin endpoint re-registered without AdminRouter loses its check, so it is refused too
    copied = FastAPI()
    copied.get("/api/admin/turnout-copy")(admin.turnout)
    with pytest.raises(RuntimeError, match="turnout-copy"):
        check_admin_routes(copied)
    # Declared properly, the same check passes
    proper, ok = FastAPI(), AdminRouter(prefix="/admin")
    ok.get("/fine", permission=TURNOUT_READ)(lambda: None)
    proper.include_router(ok, prefix="/api")
    check_admin_routes(proper)


def test_every_admin_route_has_a_mapped_permission() -> None:
    """SR-05 test 7: the real API's admin routes, each with its permission from ROLE_PERMISSIONS."""
    found = {
        (method, route.path): rbac._ADMIN_ENDPOINTS[route.endpoint]
        for route in iter_route_contexts(app.routes)
        if isinstance(route.original_route, APIRoute) and (route.path or "").startswith("/api/admin")
        for method in route.methods
    }

    assert found == {
        ("GET", "/api/admin/turnout"): "turnout:read",
        ("POST", "/api/admin/electors/{roll_id}/reset"): "elector:reset",
        ("GET", "/api/admin/audit-log"): "audit:read",
        ("GET", "/api/admin/audit-log/verify"): "audit:verify",
    }
    assert set(found.values()) <= frozenset().union(*ROLE_PERMISSIONS.values())
    check_admin_routes(app)


# ---------------------------------------------------------------
# The admin routes
# ---------------------------------------------------------------


def test_reset_route_follows_the_sr03_rules(
    client: TestClient, db_session: Session, make_voter, make_person, make_staff, sign_in, clock
) -> None:
    """SR-05 test 8: issued is cleared and the elector can be issued a ballot again; voted gets 409; unknown 404."""
    voter, official = make_voter(), make_staff("polling_official")
    roll_id = db_session.get_one(Account, voter.account_id).roll_id
    sign_in(voter)
    ballot = client.get("/api/ballot").json()
    client.post("/api/auth/logout")

    sign_in(official)
    assert call(client, "reset", roll_id).json() == {"status": "reset"}
    assert state(db_session, roll_id) is None
    assert (call(client, "reset", uuid.uuid4()).status_code, call(client, "reset", uuid.uuid4()).json()) == (
        404,
        {"detail": "not_found"},
    )
    assert call(client, "reset", make_person().roll_id).status_code == 404  # on the roll, never issued
    client.post("/api/auth/logout")

    clock.advance(seconds=30)  # a fresh authenticator code for the voter
    sign_in(voter)
    ballot = client.get("/api/ballot").json()
    assert client.post(
        "/api/ballot/submit",
        json={"ballot_token": ballot["ballot_token"], "ranked_candidate_ids": [c["id"] for c in ballot["candidates"]]},
    ).status_code == 200
    client.post("/api/auth/logout")

    clock.advance(seconds=30)
    sign_in(official)
    voted = call(client, "reset", roll_id)
    assert (voted.status_code, voted.json()) == (409, {"detail": "already_voted"})
    assert state(db_session, roll_id) == ParticipationState.VOTED


def test_turnout_holds_counts_and_nothing_about_electors(
    client: TestClient, db_session: Session, election, make_person, make_staff, sign_in
) -> None:
    """SR-05 test 9: exactly these keys, per division and in total, and no roll id, name or account."""
    people = [make_person(division=d) for d in ("Northgate", "Northgate", "Southvale")]
    for person, s in zip(people, (ParticipationState.ISSUED, ParticipationState.VOTED, ParticipationState.ISSUED)):
        db_session.add(VoterParticipation(roll_id=person.roll_id, election_id=election.election.id, state=s))
    db_session.commit()
    sign_in(make_staff("auditor"))

    response = call(client, "turnout")
    body = response.json()

    assert set(body) == {"election", "divisions", "total"}
    assert all(set(d) == {"division", "issued", "voted"} for d in body["divisions"])
    assert body["divisions"] == [
        {"division": "Northgate", "issued": 1, "voted": 1},
        {"division": "Southvale", "issued": 1, "voted": 0},
    ]
    assert body["total"] == {"issued": 2, "voted": 1}
    assert not [p for p in people if str(p.roll_id) in response.text or p.surname in response.text]


def test_audit_verify_finds_an_altered_entry(
    client: TestClient, db_session: Session, make_staff, sign_in
) -> None:
    """SR-05 test 10: ok on a clean chain; after one entry is changed in the database, that entry is reported."""
    sign_in(make_staff("auditor"))
    clean = call(client, "verify").json()
    assert clean["ok"] is True and clean["entries"] >= 2

    entries = db_session.scalars(select(AuditLogEntry).order_by(AuditLogEntry.id)).all()
    altered = entries[-2]
    db_session.execute(update(AuditLogEntry).where(AuditLogEntry.id == altered.id).values(actor="unknown"))
    db_session.commit()

    assert call(client, "verify").json() == {"ok": False, "first_bad_id": altered.id}


def test_audit_log_route_pages_in_order(client: TestClient, make_staff, sign_in) -> None:
    """SR-05: entries in id order with the stored hashes, and limit capped at 200."""
    sign_in(make_staff("auditor"))

    page = client.get("/api/admin/audit-log", params={"limit": 1000, "offset": 0}).json()

    assert [e["id"] for e in page] == sorted(e["id"] for e in page) and len(page) <= 200
    assert set(page[0]) == {"id", "created_at", "actor", "event_type", "prev_hash", "hash"}
    assert all(len(e["hash"]) == 64 and len(e["prev_hash"]) == 64 for e in page)


@pytest.mark.parametrize(
    ("role", "has_roll"), [("superuser", False), ("elector", False), ("auditor", True), ("polling_official", True)]
)
def test_database_refuses_impossible_accounts(db_session: Session, make_person, role: str, has_roll: bool) -> None:
    """SR-05 test 11: an unknown role, an elector without a roll entry, or staff with one are refused by the database."""
    roll_id = make_person().roll_id if has_roll else None

    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.execute(
            text(
                "INSERT INTO accounts (username, password_hash, role, roll_id, totp_secret_enc) "
                "VALUES (:username, 'x', :role, :roll_id, :secret)"
            ),
            {"username": f"bad.{role}", "role": role, "roll_id": roll_id, "secret": b"\x00"},
        )


# ---------------------------------------------------------------
# The staff script and the audit log
# ---------------------------------------------------------------


def test_create_staff_script(db_session: Session, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """SR-05 test 12: Argon2id, an encrypted code secret, the role, STAFF_CREATED; duplicates and bad roles refused."""
    monkeypatch.setattr(create_staff_script, "SessionLocal", lambda: nullcontext(db_session))
    monkeypatch.setattr(create_staff_script, "getpass", lambda prompt="": "auditor password one")

    create_staff_script.main(["--username", "new.auditor", "--role", "auditor"])

    printed = capsys.readouterr().out
    account = db_session.scalars(select(Account).where(Account.username == "new.auditor")).one()
    secret = decrypt(account.totp_secret_enc, "accounts.totp_secret")
    assert (account.role, account.roll_id) == (AccountRole.AUDITOR, None)
    assert account.password_hash.startswith("$argon2id$") and verify_password(account.password_hash, "auditor password one")
    assert secret.encode() not in account.totp_secret_enc
    assert "otpauth://totp/" in printed and secret in printed and "auditor password one" not in printed
    created = db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.event_type == "STAFF_CREATED")).one()
    assert (created.actor, created.details) == ("system", {"account": str(account.id), "role": "auditor"})

    for argv in (
        ["--username", "NEW.AUDITOR", "--role", "auditor"],  # taken, whatever the letter case
        ["--username", "someone.else", "--role", "elector"],
        ["--username", "someone.else", "--role", "superuser"],
    ):
        with pytest.raises(SystemExit):
            create_staff_script.main(argv)
    answers = iter(["auditor password one", "a different password"])
    monkeypatch.setattr(create_staff_script, "getpass", lambda prompt="": next(answers))
    with pytest.raises(SystemExit, match="do not match"):
        create_staff_script.main(["--username", "someone.else", "--role", "auditor"])
    monkeypatch.setattr(create_staff_script, "getpass", lambda prompt="": "too short")
    with pytest.raises(SystemExit, match="at least 12"):
        create_staff_script.main(["--username", "someone.else", "--role", "auditor"])
    assert db_session.scalar(select(func.count()).select_from(Account)) == 1


def test_denials_and_resets_are_audited_without_secrets(
    client: TestClient, db_session: Session, make_staff, sign_in, issued_elector
) -> None:
    """SR-05 test 13: AUTHZ_DENIED and ELECTOR_RESET by account only; unauthenticated 401s write nothing."""
    before = last_id(db_session)
    for route in ROUTES:
        assert call(client, route, issued_elector.roll_id).status_code == 401
    assert last_id(db_session) == before

    auditor, official = make_staff("auditor"), make_staff("polling_official")
    sign_in(auditor)
    secrets = [client.cookies[SESSION_COOKIE]]
    call(client, "reset", issued_elector.roll_id)
    client.post("/api/auth/logout")
    sign_in(official)
    secrets.append(client.cookies[SESSION_COOKIE])
    call(client, "audit_log")
    call(client, "reset", issued_elector.roll_id)

    rows = audit_since(db_session, before, "AUTHZ_DENIED", "ELECTOR_RESET")
    assert [(r.event_type, r.actor, r.details) for r in rows] == [
        ("AUTHZ_DENIED", f"account:{auditor.account_id}", {"permission": "elector:reset"}),
        ("AUTHZ_DENIED", f"account:{official.account_id}", {"permission": "audit:read"}),
        ("ELECTOR_RESET", f"staff:{official.account_id}", {}),
    ]
    secrets += [auditor.password, auditor.totp_secret, official.password, official.totp_secret]
    recorded = json.dumps([[r.event_type, r.actor, r.details] for r in audit_since(db_session, before)])
    assert [s for s in secrets if s in recorded] == []
