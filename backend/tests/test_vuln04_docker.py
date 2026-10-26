"""
VULN-04: the API image copied the whole backend folder (COPY . .) with only .env and caches left
out, so keys/ (the ballot key and the private signing keys), backups, checkpoints and any *.pem or
*.key went into the image; and it started plain uvicorn on 0.0.0.0:8000 instead of the SR-10 TLS
launcher. The fix: .dockerignore leaves out every secret and generated folder, and the container
runs python -m app.serve (TLS 1.3 only), with the certificate and keys mounted at run time.
These tests read the two files as Docker would; the real build is in the README's run command.
"""

import re
from pathlib import Path

import pytest

from app import serve
from app.config import BACKEND_DIR, settings
from scripts.dev_certs import generate_dev_cert

DOCKERIGNORE = BACKEND_DIR / ".dockerignore"
DOCKERFILE = BACKEND_DIR / "Dockerfile"

# What must never reach the image, as paths inside the build context (backend/)
SECRETS = [
    "keys/ballot.key",
    "keys/roll_private.pem",
    "keys/delegates/delegate_a.pem",
    "certs/dev-key.pem",
    "backups/20261026T000000Z_x/manifest.json",
    "checkpoints/election.jsonl",
    "releases/election/v1/dataset.json",
    "exports/ballots.jsonl",
    "monitoring/availability.jsonl",
    ".env",
    ".env.production",
    "server.pem",
    "app/stray/server.key",
    "scripts/deep/nested/private.pem",
]
NEEDED = ["app/main.py", "app/serve.py", "scripts/dev_certs.py", "migrations/env.py", "alembic.ini", "requirements.txt", ".env.example"]


def patterns() -> list[tuple[bool, re.Pattern[str]]]:
    """The .dockerignore rules, in order, as (exception?, regex), following Docker's matching."""
    rules = []
    for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        pattern = line.lstrip("!").strip("/")
        regex = ""
        index = 0
        while index < len(pattern):
            if pattern.startswith("**/", index):
                regex, index = regex + "(?:.*/)?", index + 3
            elif pattern.startswith("**", index):
                regex, index = regex + ".*", index + 2
            elif pattern[index] == "*":
                regex, index = regex + "[^/]*", index + 1
            elif pattern[index] == "?":
                regex, index = regex + "[^/]", index + 1
            else:
                regex, index = regex + re.escape(pattern[index]), index + 1
        rules.append((negated, re.compile(regex)))
    return rules


def excluded(path: str) -> bool:
    """Docker: the last rule that matches the path, or one of its parent folders, decides."""
    parts = path.split("/")
    candidates = ["/".join(parts[: n + 1]) for n in range(len(parts))]
    result = False
    for negated, regex in patterns():
        if any(regex.fullmatch(candidate) for candidate in candidates):
            result = not negated
    return result


@pytest.mark.parametrize("path", SECRETS)
def test_secrets_and_generated_data_stay_out_of_the_image(path: str) -> None:
    """VULN-04 attack 1: each of these, if present, would be copied into the image."""
    assert excluded(path), f"{path} would be copied into the image"


@pytest.mark.parametrize("path", NEEDED)
def test_the_code_still_goes_into_the_image(path: str) -> None:
    assert not excluded(path)


def test_every_real_key_and_certificate_on_disk_is_excluded() -> None:
    """VULN-04: whatever this machine's backend/ holds now (keys/, *.pem, *.key) is left out."""
    on_disk = [
        path.relative_to(BACKEND_DIR).as_posix()
        for path in BACKEND_DIR.rglob("*")
        if path.is_file() and ".venv" not in path.parts and (path.suffix in (".pem", ".key") or "keys" in path.parts)
    ]
    assert [path for path in on_disk if not excluded(path)] == []


def test_the_container_starts_through_the_tls_launcher() -> None:
    """VULN-04 attack 2: the image runs python -m app.serve (SR-10), never plain uvicorn, on the HTTPS port only."""
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    [cmd] = re.findall(r"^CMD (.+)$", dockerfile, re.MULTILINE)

    assert cmd.strip() == '["python", "-m", "app.serve"]'
    assert "uvicorn" not in cmd and re.search(r"^EXPOSE 8443$", dockerfile, re.MULTILINE)
    assert not re.search(r"^EXPOSE 8000$", dockerfile, re.MULTILINE)
    assert re.search(r"SERVER_HOST=0\.0\.0\.0", dockerfile)
    assert "USER api" in dockerfile  # still an ordinary user


def test_the_launcher_listens_on_the_configured_host(cert_files, monkeypatch) -> None:
    """VULN-04: SERVER_HOST (default 127.0.0.1) is where the TLS launcher listens; the container sets 0.0.0.0."""
    assert settings.server_host == "127.0.0.1"
    monkeypatch.setattr(settings, "server_host", "0.0.0.0")

    config = serve.tls_config(*cert_files, port=8443)

    assert (config.host, config.is_ssl) == ("0.0.0.0", True)


@pytest.fixture
def cert_files(tmp_path: Path) -> tuple[Path, Path]:
    """SR-10: a fresh development certificate and key, from the same function as scripts.dev_certs."""
    return generate_dev_cert(tmp_path / "certs")
