"""
SR-05: creates a staff account: a polling official or an auditor. Staff are
not on the electoral roll and cannot vote. No API endpoint creates staff: only
someone who can run this script against the database can.

Run from the backend folder, with the virtual environment active:
    python -m scripts.create_staff --username NAME --role polling_official|auditor

The password is asked for twice and never shown. The authenticator setup link
and key are printed once, for the staff member's authenticator app. Staff then
sign in like anyone else, with POST /api/auth/login and POST /api/auth/verify.
"""

import argparse
import re
from getpass import getpass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.db import SessionLocal
from app.models import Account, AccountRole, RegistrationSession
from app.audit_events import SUCCESS
from app.security import account_actor, audit, encrypt, hash_password, new_totp_secret, totp_uri

STAFF_ROLES = [AccountRole.POLLING_OFFICIAL.value, AccountRole.AUDITOR.value]


def create_staff(session: Session, username: str, role: str, password: str) -> tuple[str, str]:
    """
    Creates the account, audits STAFF_CREATED and returns the authenticator setup
    link and key. Raises SystemExit, creating nothing, if anything is refused.
    """
    username = username.strip()
    if role not in STAFF_ROLES:
        raise SystemExit(f"The role must be one of: {', '.join(STAFF_ROLES)}.")
    # The same minimum rules as registration (app/routers/register.py)
    if not re.fullmatch(config.USERNAME_PATTERN, username):
        raise SystemExit("A username is 3 to 32 letters, digits, dots or underscores.")
    if len(password) < config.PASSWORD_MIN_LENGTH:
        raise SystemExit(f"The password must be at least {config.PASSWORD_MIN_LENGTH} characters.")
    if password.casefold() == username.casefold():
        raise SystemExit("The password must not be the username.")
    # Both columns are citext, so letter case does not matter, as in registration
    taken = session.scalar(select(Account.id).where(Account.username == username)) or session.scalar(
        select(RegistrationSession.id_hash).where(RegistrationSession.username == username)
    )
    if taken:
        raise SystemExit(f"The username {username} is already in use. Nothing was created.")

    secret = new_totp_secret()
    account = Account(
        username=username,
        password_hash=hash_password(password),
        role=AccountRole(role),
        roll_id=None,
        totp_secret_enc=encrypt(secret, "accounts.totp_secret"),
    )
    session.add(account)
    session.flush()
    # SR-16: the actor is the account created, with the role it was given. Only this script makes
    # staff accounts, on the server, and it has no account of its own; the username is never recorded.
    actor, actor_role = account_actor(account)
    audit(session, "STAFF_CREATED", outcome=SUCCESS, actor=actor, role=actor_role)
    session.commit()
    return totp_uri(secret, username), secret


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Create a staff account (development and administration).")
    parser.add_argument("--username", required=True)
    parser.add_argument("--role", required=True, choices=STAFF_ROLES)
    args = parser.parse_args(argv)

    password = getpass("Password: ")
    if getpass("Password again: ") != password:
        raise SystemExit("The passwords do not match. Nothing was created.")
    with SessionLocal() as session:
        uri, secret = create_staff(session, args.username, args.role, password)

    print(f"Created the {args.role} account {args.username.strip()}.")
    print("Add it to the authenticator app now. This is the only time it is shown:")
    print(f"  Setup link: {uri}")
    print(f"  Setup key:  {secret}")


if __name__ == "__main__":
    main()
