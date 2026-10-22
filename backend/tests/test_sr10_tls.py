"""
SR-10: ballots travel only over TLS 1.3. The handshakes run in memory (ssl.MemoryBIO) with the
exact SSL context python -m app.serve listens with, so no test opens a port or starts a server.
"""

import ssl
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import serve
from app.config import Settings, settings
from app.main import app, serve_frontend
from app.models import AuditLogEntry, AuthSession
from scripts.dev_certs import generate_dev_cert

HTTP_REQUEST = b"GET /api/health HTTP/1.1\r\nHost: localhost:8443\r\n\r\n"


@pytest.fixture
def cert_files(tmp_path: Path) -> tuple[Path, Path]:
    """SR-10: a fresh development certificate and key, from the same function as scripts.dev_certs."""
    return generate_dev_cert(tmp_path / "certs")


@pytest.fixture
def server_context(cert_files: tuple[Path, Path]) -> ssl.SSLContext:
    """SR-10: the SSL context the server would listen with (serve.tls_config, as python -m app.serve)."""
    context = serve.tls_config(*cert_files, port=8443).ssl
    assert context is not None
    return context


def trusting_client(cert: Path) -> ssl.SSLContext:
    """SR-10: a client that trusts the development certificate, as a browser does once it is installed."""
    context = ssl.create_default_context(cafile=str(cert))
    context.verify_flags |= ssl.VERIFY_X509_STRICT  # the stricter checks newer Pythons turn on by default
    return context


def handshake(
    server_context: ssl.SSLContext, client_context: ssl.SSLContext, server_hostname: str = "localhost"
) -> tuple[ssl.SSLObject, ssl.SSLObject]:
    """SR-10: a full TLS handshake between two in-memory ends. Raises ssl.SSLError if it fails."""
    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_in, client_out, server_hostname=server_hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    pending = [client, server]
    for _ in range(10):
        for end in list(pending):
            try:
                end.do_handshake()
                pending.remove(end)
            except ssl.SSLWantReadError:
                pass
        server_in.write(client_out.read())
        client_in.write(server_out.read())
        if not pending:
            return client, server
    raise AssertionError("the handshake did not finish")


# ---------------------------------------------------------------
# The TLS server context
# ---------------------------------------------------------------


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_tls13_client_that_trusts_the_certificate_connects(
    server_context: ssl.SSLContext, cert_files: tuple[Path, Path], host: str
) -> None:
    """SR-10 test 1: a TLS 1.3 client that trusts the certificate completes the handshake, on TLS 1.3."""
    client_context = trusting_client(cert_files[0])
    client_context.minimum_version = ssl.TLSVersion.TLSv1_3

    client, server = handshake(server_context, client_context, host)

    assert client.version() == server.version() == "TLSv1.3"
    assert ("DNS", "localhost") in client.getpeercert()["subjectAltName"]


def test_tls12_client_is_refused(server_context: ssl.SSLContext, cert_files: tuple[Path, Path]) -> None:
    """SR-10 test 2: a client limited to TLS 1.2 cannot complete the handshake."""
    client_context = trusting_client(cert_files[0])
    client_context.maximum_version = ssl.TLSVersion.TLSv1_2

    with pytest.raises(ssl.SSLError) as refused:
        handshake(server_context, client_context)

    assert refused.value.reason == "UNSUPPORTED_PROTOCOL"


def test_client_that_does_not_trust_the_certificate_fails(server_context: ssl.SSLContext) -> None:
    """SR-10 test 3: a client with only the default trust store rejects the certificate."""
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake(server_context, ssl.create_default_context())


def test_wrong_host_name_fails(server_context: ssl.SSLContext, cert_files: tuple[Path, Path]) -> None:
    """SR-10 test 4: a name that is not in the certificate's subjectAltName fails validation."""
    with pytest.raises(ssl.SSLCertVerificationError, match="Hostname mismatch"):
        handshake(server_context, trusting_client(cert_files[0]), "evoting.example")


def test_plaintext_http_gets_no_http_response(server_context: ssl.SSLContext) -> None:
    """SR-10 test 5: an HTTP request sent to the TLS port ends the connection: no handshake, no HTTP reply."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = server_context.wrap_bio(incoming, outgoing, server_side=True)
    incoming.write(HTTP_REQUEST)

    with pytest.raises(ssl.SSLError):
        server.do_handshake()

    assert b"HTTP/" not in outgoing.read()


def test_serve_builds_a_tls13_only_server(cert_files: tuple[Path, Path]) -> None:
    """SR-10 test 6: python -m app.serve listens with TLS on 127.0.0.1 only, TLS 1.3 at least, no proxy headers."""
    config = serve.tls_config(*cert_files, port=8443)

    assert config.is_ssl and config.ssl is not None
    assert config.ssl.minimum_version == ssl.TLSVersion.TLSv1_3
    assert (config.host, config.port, config.proxy_headers, config.reload) == ("127.0.0.1", 8443, False, False)


@pytest.mark.parametrize("missing", ["certificate", "key"])
def test_serve_refuses_to_start_without_certificate_or_key(
    cert_files: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    """SR-10 test 7: no certificate or no key: exit non-zero with how to make them; never a plaintext server."""
    cert, key = cert_files
    (cert if missing == "certificate" else key).unlink()
    monkeypatch.setattr(settings, "tls_cert_file", cert)
    monkeypatch.setattr(settings, "tls_key_file", key)
    monkeypatch.setattr(serve.uvicorn, "Server", lambda *args, **kwargs: pytest.fail("a server was started"))

    with pytest.raises(SystemExit) as stopped:
        serve.main()

    assert stopped.value.code not in (0, None)
    assert "python -m scripts.dev_certs" in str(stopped.value.code)


# ---------------------------------------------------------------
# The app: plaintext refused, HSTS on every HTTPS response
# ---------------------------------------------------------------


def test_plaintext_request_is_refused_before_any_route_runs(
    client: TestClient, db_session: Session, make_voter
) -> None:
    """SR-10 test 8: over http:// even a correct sign-in gets 400 tls_required, and nothing runs or is written."""
    voter = make_voter()
    audit_rows = db_session.scalar(select(func.count()).select_from(AuditLogEntry))
    plaintext = TestClient(app, base_url="http://testserver")

    health = plaintext.get("/api/health")
    login = plaintext.post("/api/auth/login", json={"username": voter.username, "password": voter.password})

    for response in (health, login):
        assert (response.status_code, response.json()) == (400, {"detail": "tls_required"})
        assert "set-cookie" not in response.headers
        # HSTS means nothing over plain HTTP (RFC 6797); SR-09's no-store still applies
        assert "strict-transport-security" not in response.headers
        assert (response.headers["cache-control"], response.headers["pragma"]) == ("no-store", "no-cache")
    assert db_session.scalar(select(func.count()).select_from(AuthSession)) == 0
    assert db_session.scalar(select(func.count()).select_from(AuditLogEntry)) == audit_rows


def test_https_request_works_and_carries_hsts(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-10 test 9: the same request over https:// works, with HSTS at the configured max-age."""
    monkeypatch.setattr(settings, "hsts_max_age", 300)

    response = client.get("/api/health")

    assert (response.status_code, response.json()) == (200, {"status": "ok"})
    assert response.headers["strict-transport-security"] == "max-age=300"
    assert response.headers["cache-control"] == "no-store"


def test_hsts_default_is_one_year(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-10 test 10: without HSTS_MAX_AGE the header says one year (31536000 seconds)."""
    default = Settings.model_fields["hsts_max_age"].default
    monkeypatch.setattr(settings, "hsts_max_age", default)

    assert default == 31536000
    assert client.get("/api/health").headers["strict-transport-security"] == "max-age=31536000"


@pytest.mark.parametrize(
    ("expected", "send"),
    [
        pytest.param(401, lambda c: c.get("/api/ballot"), id="not-signed-in"),
        pytest.param(404, lambda c: c.get("/api/no-such-route"), id="unknown-path"),
        pytest.param(422, lambda c: c.post("/api/auth/login", json={}), id="invalid-body"),
        pytest.param(307, lambda c: c.get("/api/health/", follow_redirects=False), id="redirect"),
    ],
)
def test_hsts_and_no_store_on_error_responses(client: TestClient, expected: int, send) -> None:
    """SR-10 test 11: HSTS is on 4xx answers and redirects too, and SR-09's no-store is still there."""
    response = send(client)

    assert response.status_code == expected
    assert response.headers["strict-transport-security"] == f"max-age={settings.hsts_max_age}"
    assert (response.headers["cache-control"], response.headers["pragma"]) == ("no-store", "no-cache")


# ---------------------------------------------------------------
# The built frontend, on the same HTTPS entry point
# ---------------------------------------------------------------


def test_built_frontend_is_served_without_shadowing_the_api(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-10 test 12: index.html and staff.html come over HTTPS with HSTS, and every /api path still reaches the API."""
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<p>voter app</p>", encoding="utf-8")
    (dist / "staff.html").write_text("<p>staff page</p>", encoding="utf-8")
    monkeypatch.setattr(app.router, "default", app.router.default)  # put back after the test
    serve_frontend(app, dist)

    voter, staff = client.get("/"), client.get("/staff.html")

    assert (voter.status_code, voter.text, staff.text) == (200, "<p>voter app</p>", "<p>staff page</p>")
    assert voter.headers["strict-transport-security"] and voter.headers["cache-control"] == "no-store"
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/api/health/", follow_redirects=False).status_code == 307
    missing = client.get("/api/no-such-route")
    assert (missing.status_code, missing.json()) == (404, {"detail": "Not Found"})


def test_without_a_build_the_api_still_runs(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-10 test 13: with no frontend/dist (tests, CI) the app starts and the API works."""
    monkeypatch.setattr(app.router, "default", app.router.not_found)

    serve_frontend(app, tmp_path / "no-build-here")

    assert app.router.default == app.router.not_found
    assert client.get("/api/health").status_code == 200
    assert client.get("/").status_code == 404
