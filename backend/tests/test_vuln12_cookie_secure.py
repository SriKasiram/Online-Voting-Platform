"""
VULN-12: the registration cookie was set, and cleared, without the Secure attribute, so a browser
would send it over plain HTTP. The fix: every cookie the platform sets or clears takes the session
cookie's COOKIE_SECURE setting.
"""

import re

import pyotp
import pytest
from fastapi.testclient import TestClient

from app.config import BACKEND_DIR, settings
from app.security import REGISTRATION_COOKIE, SESSION_COOKIE

VERIFY = "/api/register/verify"
ACCOUNT = "/api/register/account"
CONFIRM = "/api/register/confirm"


def set_cookie_headers(response, name: str) -> list[str]:
    return [value for key, value in response.headers.multi_items() if key == "set-cookie" and value.startswith(f"{name}=")]


def attributes(header: str) -> set[str]:
    return {part.strip().split("=")[0].lower() for part in header.split(";")[1:]}


def register_all_three_steps(client: TestClient, person) -> tuple:
    started = client.post(VERIFY, json=person.verify_body())
    secret = client.post(ACCOUNT, json={"username": "secure.cookie", "password": "a long enough password"}).json()["secret"]
    finished = client.post(CONFIRM, json={"otp_code": pyotp.TOTP(secret).now()})
    return started, finished


def test_the_registration_cookie_is_set_and_cleared_with_secure(client: TestClient, make_person) -> None:
    """VULN-12 attack: with COOKIE_SECURE on (the default), both Set-Cookie headers for the registration cookie say Secure."""
    started, finished = register_all_three_steps(client, make_person())

    [set_header] = set_cookie_headers(started, REGISTRATION_COOKIE)
    [cleared_header] = set_cookie_headers(finished, REGISTRATION_COOKIE)
    assert finished.status_code == 204 and re.search(r"max-age=0", cleared_header, re.IGNORECASE)
    assert "secure" in attributes(set_header) and "secure" in attributes(cleared_header)
    assert {"httponly", "samesite", "path"} <= attributes(set_header)


@pytest.mark.parametrize("secure", [True, False])
def test_every_cookie_follows_cookie_secure(client: TestClient, make_person, make_voter, sign_in, monkeypatch, secure: bool) -> None:
    """VULN-12: the session and registration cookies, set and cleared, all carry Secure exactly when COOKIE_SECURE is on."""
    monkeypatch.setattr(settings, "cookie_secure", secure)
    started, finished = register_all_three_steps(client, make_person())
    signed_in = sign_in(make_voter())
    signed_out = client.post("/api/auth/logout")

    headers = (
        set_cookie_headers(started, REGISTRATION_COOKIE)
        + set_cookie_headers(finished, REGISTRATION_COOKIE)
        + set_cookie_headers(signed_in, SESSION_COOKIE)
        + set_cookie_headers(signed_out, SESSION_COOKIE)
    )
    assert len(headers) == 4
    assert {("secure" in attributes(header)) for header in headers} == {secure}


def test_cookies_are_only_set_through_the_shared_helpers() -> None:
    """VULN-12: no route sets or deletes a cookie itself, so none can miss the setting."""
    direct = [
        f"{path.relative_to(BACKEND_DIR)}:{number}"
        for path in (BACKEND_DIR / "app").rglob("*.py")
        if path.name != "security.py"
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if re.search(r"\.(set_cookie|delete_cookie)\(", line)
    ]

    assert direct == []
