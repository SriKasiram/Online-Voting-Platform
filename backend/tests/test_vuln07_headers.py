"""
VULN-07: responses carried no Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy or Permissions-Policy, so the pages could be framed (clickjacking), injected script
would run unrestricted, and the browser could sniff content types. The fix: one middleware sets them
on every response, beside the existing Cache-Control (SR-09), HSTS (SR-10) and X-Request-ID (SR-16).
"""

import re
from pathlib import Path

import pytest
from fastapi.staticfiles import StaticFiles
from fastapi.testclient import TestClient

from app.config import PROJECT_DIR
from app.main import app

CSP = (
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'self'; img-src 'self' data:"
)
EXPECTED = {
    "content-security-policy": CSP,
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}
DIST = PROJECT_DIR / "frontend" / "dist"


def assert_hardened(response) -> None:
    assert {name: response.headers.get(name) for name in EXPECTED} == EXPECTED
    policy = response.headers["permissions-policy"]
    for feature in ("camera", "microphone", "geolocation", "payment", "usb", "display-capture"):
        assert f"{feature}=()" in policy
    # kept: SR-09, SR-10 and SR-16
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["strict-transport-security"].startswith("max-age=")


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("GET", "/api/health", None),
        ("GET", "/api/ballot", 401),
        ("GET", "/api/no-such-route", 404),
        ("POST", "/api/auth/login", 422),
    ],
)
def test_every_api_response_carries_the_headers(client: TestClient, method: str, path: str, status: int | None) -> None:
    """VULN-07 attack 1: answers, errors and unknown paths alike, with the SR-09, SR-10 and SR-16 headers kept."""
    response = client.request(method, path, json={} if method == "POST" else None)

    assert status is None or response.status_code == status
    assert_hardened(response)
    assert re.fullmatch(r"[0-9a-f-]{36}", response.headers["x-request-id"])


@pytest.fixture
def built_pages(tmp_path: Path, monkeypatch) -> Path:
    """The built elector and staff pages, served as python -m app.serve serves them (the real build if there is one)."""
    folder = DIST
    if not (folder / "index.html").is_file():
        folder = tmp_path / "dist"
        folder.mkdir()
        for page in ("index.html", "staff.html"):
            (folder / page).write_text('<!doctype html><script type="module" src="/assets/main.js"></script>', encoding="utf-8")
    monkeypatch.setattr(app.router, "default", StaticFiles(directory=folder, html=True))
    return folder


@pytest.mark.parametrize("page", ["/", "/staff.html"])
def test_the_built_elector_and_staff_pages_carry_the_headers(client: TestClient, built_pages: Path, page: str) -> None:
    """VULN-07 attack 2: the pages a browser actually renders get the policy too."""
    response = client.get(page)

    assert response.status_code == 200 and "text/html" in response.headers["content-type"]
    assert_hardened(response)


def test_the_built_pages_need_nothing_the_policy_forbids() -> None:
    """VULN-07: no inline script, inline style, inline handler or other origin in the build; data: only for images in CSS."""
    if not (DIST / "index.html").is_file():
        pytest.skip("the frontend is not built (npm run build); the browser check in the README covers it")
    pages = [(DIST / name).read_text(encoding="utf-8") for name in ("index.html", "staff.html")]
    css = "".join(path.read_text(encoding="utf-8") for path in (DIST / "assets").glob("*.css"))
    for page in pages:
        assert all(re.search(r'\bsrc="/', tag) for tag in re.findall(r"<script\b[^>]*>", page)), "inline script"
        assert not re.search(r"<style\b|\sstyle=|\son[a-z]+=", page), "inline style or handler"
        assert not re.search(r'(?:src|href)="(?:https?:)?//', page), "another origin"
    assert set(re.findall(r"url\((?:\"|')?(data:[a-z/+.-]+)", css)) <= {"data:image/svg+xml"}
    assert not re.search(r"url\((?:\"|')?(?:https?:)?//", css)


def test_the_tls_refusal_is_hardened_too(client: TestClient) -> None:
    """VULN-07, SR-10: even the plain-HTTP refusal, which never reaches the inner middleware, gets the headers."""
    plain = TestClient(app, base_url="http://testserver").get("/api/health")

    assert plain.status_code == 400
    assert {name: plain.headers.get(name) for name in EXPECTED} == EXPECTED
