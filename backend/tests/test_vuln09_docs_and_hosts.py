"""
VULN-09: FastAPI served /docs, /redoc and /openapi.json to anyone, a map of every route and field;
and any Host header was accepted. The fix: the docs are off unless API_DOCS is on (and then only
those paths get a CSP relaxed for the docs page's scripts), and a trusted-host check refuses any
Host not in TRUSTED_HOSTS (default localhost and 127.0.0.1).
"""

import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from app.config import BACKEND_DIR, settings
from app.main import app


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"])
def test_api_docs_are_off_by_default(client: TestClient, path: str) -> None:
    """VULN-09 attack 1: no route map for an outsider."""
    response = client.get(path)

    assert response.status_code == 404
    assert "openapi" not in response.text.lower() and "swagger" not in response.text.lower()


def run_with_docs_on(script: str) -> dict:
    """The app as it starts with API_DOCS=true, in a fresh interpreter (the setting is read at start-up)."""
    env = os.environ | {"API_DOCS": "true", "TRUSTED_HOSTS": '["testserver"]'}
    done = subprocess.run([sys.executable, "-c", script], cwd=BACKEND_DIR, env=env, capture_output=True, text=True, check=False, timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


DOCS_ON = """
import json
from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app, base_url="https://testserver")
docs, schema, health = client.get("/docs"), client.get("/openapi.json"), client.get("/api/health")
print(json.dumps({
    "docs": docs.status_code, "schema": schema.status_code,
    "docs_csp": docs.headers.get("content-security-policy"),
    "health_csp": health.headers.get("content-security-policy"),
}))
"""


def test_api_docs_can_be_switched_on_with_a_relaxed_policy_on_their_paths_only() -> None:
    """VULN-09: API_DOCS=true serves them, and only those paths get the docs policy."""
    seen = run_with_docs_on(DOCS_ON)

    assert (seen["docs"], seen["schema"]) == (200, 200)
    assert "https://cdn.jsdelivr.net" in seen["docs_csp"] and "frame-ancestors 'none'" in seen["docs_csp"]
    assert "cdn.jsdelivr.net" not in seen["health_csp"] and "'unsafe-inline'" not in seen["health_csp"]


@pytest.mark.parametrize("host", ["evil.example", "localhost.evil.example", "10.0.0.5"])
def test_a_host_header_that_is_not_trusted_is_refused(client: TestClient, host: str) -> None:
    """VULN-09 attack 2: a request naming another host is refused before any route runs."""
    response = TestClient(app, base_url=f"https://{host}").get("/api/health")

    assert (response.status_code, response.json()) == (400, {"detail": "invalid_host"})
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "localhost:8443", "127.0.0.1:8443"])
def test_the_default_trusted_hosts_are_this_computer(client: TestClient, host: str, monkeypatch) -> None:
    """VULN-09: localhost and 127.0.0.1, with or without the port, as the TLS certificate names them."""
    monkeypatch.setattr(settings, "trusted_hosts", ["localhost", "127.0.0.1"])

    assert TestClient(app, base_url=f"https://{host}").get("/api/health").status_code in (200, 503)
