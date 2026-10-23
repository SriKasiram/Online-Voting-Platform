"""
SR-18: House results leave the platform only as a signed release: the exact bytes of the canonical
dataset, signed with a dedicated Ed25519 key, verifiable by a recipient with the separately
published public key.
"""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session
from test_sr17_count import CountedElection

from app.ballot_chain import checkpoint_file
from app.config import BACKEND_DIR, settings
from app.main import app
from app.models import AuditLogEntry
from app.result_dataset import SCHEMA, build_dataset, key_fingerprint
from app.security import AUDIT_FORMAT_CURRENT, verify_audit_chain
from scripts import release_results
from scripts.gen_results_key import generate_results_keys
from scripts.release_results import DATASET, INSTRUCTIONS, LOG, SIGNATURE, ReleaseRefused
from scripts.seal_ballots import load_private_key, seal_batch

VERIFIER = BACKEND_DIR / "scripts" / "verify_release.py"


def make_keys(folder: Path):
    """SR-18: a fresh results key pair, made by the key script's own function."""
    private_path, public_path = generate_results_keys(folder / "results_private.pem", folder / "results_public.pem")
    return {"private_path": private_path, "public_path": public_path, "private": load_private_key(private_path)}


@pytest.fixture
def results_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """SR-18: a temporary results key pair, with the settings pointed at it."""
    keys = make_keys(tmp_path / "keys")
    monkeypatch.setattr(settings, "results_private_key", keys["private_path"])
    monkeypatch.setattr(settings, "results_public_key", keys["public_path"])
    return keys


@pytest.fixture
def releases_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """SR-18: a temporary RELEASES_DIR."""
    folder = tmp_path / "releases"
    monkeypatch.setattr(settings, "releases_dir", folder)
    return folder


def recipient_check(release_folder: Path, recipient: Path, public_pem: str, *extra: str) -> subprocess.CompletedProcess:
    """
    SR-18: what a recipient does, on their own copy: the release folder and the verifier script are
    copied elsewhere, and the copy runs in isolated mode (-I), so it cannot import the platform.
    """
    if not recipient.exists():
        shutil.copytree(release_folder, recipient)
        shutil.copy(VERIFIER, recipient / "verify_release.py")
    (recipient / "results_public.pem").write_text(public_pem, encoding="ascii")
    return subprocess.run(
        [sys.executable, "-I", "verify_release.py", "--dataset", DATASET, "--signature", SIGNATURE, "--public-key", "results_public.pem", *extra],
        cwd=recipient,
        capture_output=True,
        text=True,
        check=False,
    )


def openssl_3() -> tuple[str | None, str]:
    """SR-18: an OpenSSL 3.0+ command line, if one is installed, and the version found."""
    exe = shutil.which("openssl")
    if exe is None:
        return None, "none"
    version = subprocess.run([exe, "version"], capture_output=True, text=True, check=False).stdout.strip()
    major = re.match(r"OpenSSL (\d+)\.", version)
    return (exe if major and int(major.group(1)) >= 3 else None), version


# ---------------------------------------------------------------
# The published key (no election needed)
# ---------------------------------------------------------------


def test_public_key_route_needs_no_session_and_matches_the_signer(client: TestClient, results_keys) -> None:
    """SR-18: /api/public/results-key answers without a session, with the signer's key and fingerprint."""
    response = client.get("/api/public/results-key")

    assert response.status_code == 200
    body = response.json()
    assert body["algorithm"] == "Ed25519" and set(body) == {"algorithm", "public_key_pem", "fingerprint_sha256"}
    assert body["public_key_pem"] == results_keys["public_path"].read_text(encoding="ascii")
    assert body["fingerprint_sha256"] == key_fingerprint(results_keys["private"].public_key())
    # SR-09 and SR-10 still apply to the official page
    assert response.headers["cache-control"] == "no-store" and "max-age" in response.headers["strict-transport-security"]


def test_public_key_route_says_not_configured_and_the_app_starts_without_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    """SR-18: with no results key there is nothing to publish (404 not_configured), and start-up is unaffected."""
    monkeypatch.setattr(settings, "results_public_key", tmp_path / "missing_public.pem")
    monkeypatch.setattr(settings, "results_private_key", tmp_path / "missing_private.pem")

    response = client.get("/api/public/results-key")
    with TestClient(app, base_url="https://testserver") as started:
        health = started.get("/api/health")

    assert (response.status_code, response.json()) == (404, {"detail": "not_configured"})
    assert health.status_code == 200


def api_routes() -> list[tuple[str, set[str]]]:
    """SR-18: every API route with its methods, included routers too (as SR-05's route test reads them)."""
    return [
        (route.path, set(route.methods))
        for route in iter_route_contexts(app.routes)
        if isinstance(route.original_route, APIRoute)
    ]


def test_no_route_serves_a_result_dataset() -> None:
    """SR-18: the only results-related route is the public key; releases leave only through the script."""
    paths = {path for path, _ in api_routes()}

    assert len(paths) > 15
    assert [p for p in paths if "result" in p or "release" in p] == ["/api/public/results-key"]
    assert not [p for p in paths if p.startswith("/api/public/") and p != "/api/public/results-key"]


def test_the_verifier_is_standalone() -> None:
    """SR-18: verify_release.py imports only the standard library and cryptography: no app, no settings."""
    source = VERIFIER.read_text(encoding="utf-8")
    imports = re.findall(r"^(?:from|import) ([\w.]+)", source, re.MULTILINE)

    assert imports and all(name.split(".")[0] in {"argparse", "hashlib", "json", "sys", "pathlib", "cryptography"} for name in imports)


# ---------------------------------------------------------------
# Releases of a real, counted election
# ---------------------------------------------------------------


class TestRelease(CountedElection):
    """SR-18: releases built on the SR-17 committed election (five ballots, polls closed, final seal)."""

    def release(self, engine: Engine, election_id, keys, results_keys, releases_dir: Path, published=None):
        return release_results.release_results(
            engine,
            election_id,
            results_keys["private"],
            published or results_keys["private"].public_key(),
            keys[1],
            checkpoint_file(election_id),
            releases_dir,
        )

    def released(self, engine, election_id, keys, results_keys, releases_dir) -> Path:
        return self.release(engine, election_id, keys, results_keys, releases_dir).folder

    def events(self, db: Session, *types: str) -> list[AuditLogEntry]:
        db.expire_all()
        return list(db.scalars(select(AuditLogEntry).where(AuditLogEntry.event_type.in_(types)).order_by(AuditLogEntry.id)))

    def public_pem(self, client: TestClient) -> tuple[str, str]:
        body = client.get("/api/public/results-key").json()
        return body["public_key_pem"], body["fingerprint_sha256"]

    # -- a clean release, verified as a recipient would --

    def test_a_clean_release_creates_v1_and_a_recipient_verifies_it(
        self, engine: Engine, client: TestClient, sealed, results_keys, releases_dir: Path, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        """SR-18: the script makes v1 with the dataset, raw signature and VERIFY.txt; the standalone verifier says VALID."""
        monkeypatch.setattr(release_results, "engine", engine)
        election_id = sealed["election_id"]

        assert release_results.main(["--election", str(election_id)]) == 0

        printed = capsys.readouterr().out
        folder = releases_dir / str(election_id) / "v1"
        assert sorted(p.name for p in folder.iterdir()) == sorted([DATASET, SIGNATURE, INSTRUCTIONS])
        data, signature = (folder / DATASET).read_bytes(), (folder / SIGNATURE).read_bytes()
        assert len(signature) == 64 and not data.endswith(b"\n")
        sha = hashlib.sha256(data).hexdigest()
        assert f"Released version 1 in {folder}" in printed and f"Dataset SHA-256: {sha}" in printed
        [line] = (releases_dir / str(election_id) / LOG).read_text(encoding="utf-8").splitlines()
        logged = json.loads(line)
        assert (set(logged), logged["version"], logged["dataset_sha256"], logged["previous_release_sha256"]) == (
            {"version", "dataset_sha256", "previous_release_sha256", "generated_at"}, 1, sha, None
        )
        assert all(not os.access(folder / name, os.W_OK) for name in (DATASET, SIGNATURE, INSTRUCTIONS))

        pem, fingerprint = self.public_pem(client)
        check = recipient_check(folder, tmp_path / "recipient", pem, "--expected-fingerprint", fingerprint)

        assert check.returncode == 0, check.stdout + check.stderr
        assert check.stdout.strip() == f"VALID: election {election_id}, release version 1, final chain head {json.loads(data)['final_chain_head']}"

    def test_openssl_verifies_the_release_too(self, engine: Engine, client: TestClient, sealed, results_keys, releases_dir: Path, keys) -> None:
        """SR-18: standard tools work, because the signed bytes carry no domain tag (needs OpenSSL 3.0+)."""
        exe, version = openssl_3()
        if exe is None:
            pytest.skip(f"OpenSSL 3.0 or later is needed for Ed25519 pkeyutl -rawin; found: {version}")
        folder = self.released(engine, sealed["election_id"], keys, results_keys, releases_dir)

        result = subprocess.run(
            [exe, "pkeyutl", "-verify", "-pubin", "-inkey", str(results_keys["public_path"]), "-rawin", "-in", str(folder / DATASET), "-sigfile", str(folder / SIGNATURE)],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0 and "Signature Verified Successfully" in result.stdout

    # -- what a recipient must reject --

    def test_one_changed_byte_is_invalid(self, engine, client, sealed, results_keys, releases_dir, keys, tmp_path) -> None:
        """SR-18: one number changed in result.json, and the signature no longer matches."""
        folder = self.released(engine, sealed["election_id"], keys, results_keys, releases_dir)
        recipient = tmp_path / "recipient"
        pem, _ = self.public_pem(client)
        assert recipient_check(folder, recipient, pem).returncode == 0
        data = (recipient / DATASET).read_bytes()
        os.chmod(recipient / DATASET, stat.S_IWRITE | stat.S_IREAD)
        (recipient / DATASET).write_bytes(data.replace(b'"ballot_count":5', b'"ballot_count":6', 1))

        check = recipient_check(folder, recipient, pem)

        assert check.returncode == 1 and check.stdout.strip() == "INVALID: the signature does not match this dataset and key"

    def test_another_releases_signature_is_invalid(self, engine, client, sealed, results_keys, releases_dir, keys, tmp_path) -> None:
        """SR-18: v1's signature does not vouch for v2's data."""
        v1 = self.released(engine, sealed["election_id"], keys, results_keys, releases_dir)
        v2 = self.released(engine, sealed["election_id"], keys, results_keys, releases_dir)
        recipient = tmp_path / "mixed"
        recipient.mkdir()
        shutil.copy(v2 / DATASET, recipient / DATASET)
        shutil.copy(v1 / SIGNATURE, recipient / SIGNATURE)
        shutil.copy(VERIFIER, recipient / "verify_release.py")
        pem, _ = self.public_pem(client)

        check = recipient_check(v2, recipient, pem)

        assert check.returncode == 1 and "INVALID: the signature does not match" in check.stdout

    def test_another_key_or_a_wrong_fingerprint_is_invalid(self, engine, client, sealed, results_keys, releases_dir, keys, tmp_path) -> None:
        """SR-18: a different public key fails the signature; the right key with a wrong expected fingerprint fails too."""
        folder = self.released(engine, sealed["election_id"], keys, results_keys, releases_dir)
        other = make_keys(tmp_path / "other")
        pem, fingerprint = self.public_pem(client)

        with_other_key = recipient_check(folder, tmp_path / "a", other["public_path"].read_text(encoding="ascii"))
        wrong_fingerprint = recipient_check(folder, tmp_path / "b", pem, "--expected-fingerprint", "0" * 64)
        right = recipient_check(folder, tmp_path / "c", pem, "--expected-fingerprint", fingerprint.upper())

        assert (with_other_key.returncode, with_other_key.stdout.strip()) == (1, "INVALID: the signature does not match this dataset and key")
        assert (wrong_fingerprint.returncode, wrong_fingerprint.stdout.strip()) == (1, "INVALID: the public key's fingerprint is not the expected one")
        assert right.returncode == 0

    # -- what the platform refuses to release --

    def test_a_refused_count_releases_nothing(
        self, engine: Engine, db_session: Session, election, cast, keys, results_keys, releases_dir: Path
    ) -> None:
        """SR-18: polls still open: the SR-17 count refuses, so no folder, no log line, and both refusals are audited."""
        cast("Northgate", [0, 1, 2])
        election_id = election.election.id
        seal_batch(db_session, election_id, True, *keys, checkpoint_file(election_id))

        with pytest.raises(ReleaseRefused) as refused:
            self.release(engine, election_id, keys, results_keys, releases_dir)

        assert refused.value.code == "polls_open"
        assert not (releases_dir / str(election_id)).exists()
        assert [(e.event_type, e.reason) for e in self.events(db_session, "COUNT_REFUSED", "RESULT_RELEASE_REFUSED")] == [
            ("COUNT_REFUSED", "polls_open"),
            ("RESULT_RELEASE_REFUSED", "polls_open"),
        ]

    def test_an_existing_version_folder_is_never_overwritten(self, engine, db_session, sealed, results_keys, releases_dir, keys) -> None:
        """SR-18: v1's folder already exists (unlogged): version_exists, and nothing in it changes."""
        folder = releases_dir / str(sealed["election_id"]) / "v1"
        folder.mkdir(parents=True)
        (folder / "keep.txt").write_text("already here", encoding="utf-8")

        with pytest.raises(ReleaseRefused) as refused:
            self.release(engine, sealed["election_id"], keys, results_keys, releases_dir)

        assert (refused.value.code, refused.value.version) == ("version_exists", 1)
        assert [p.name for p in folder.iterdir()] == ["keep.txt"] and (folder / "keep.txt").read_text(encoding="utf-8") == "already here"
        assert not (folder.parent / LOG).exists()
        assert [(e.reason, e.version) for e in self.events(db_session, "RESULT_RELEASE_REFUSED")] == [("version_exists", 1)]

    def test_a_second_release_is_v2_and_names_v1(self, engine, sealed, results_keys, releases_dir, keys) -> None:
        """SR-18: a correction is a new version: v2's previous_release_sha256 is the SHA-256 of v1's result.json."""
        v1 = self.release(engine, sealed["election_id"], keys, results_keys, releases_dir)
        v2 = self.release(engine, sealed["election_id"], keys, results_keys, releases_dir)

        v1_sha = hashlib.sha256((v1.folder / DATASET).read_bytes()).hexdigest()
        dataset = json.loads((v2.folder / DATASET).read_bytes())
        assert (v2.version, dataset["release_version"], dataset["previous_release_sha256"]) == (2, 2, v1_sha)
        assert json.loads((v1.folder / DATASET).read_bytes())["previous_release_sha256"] is None
        assert len((v1.folder.parent / LOG).read_text(encoding="utf-8").splitlines()) == 2

    def test_an_edited_release_blocks_the_next_one(self, engine, db_session, sealed, results_keys, releases_dir, keys) -> None:
        """SR-18: v1's result.json edited after release: the next release refuses with release_history_invalid."""
        v1 = self.released(engine, sealed["election_id"], keys, results_keys, releases_dir)
        os.chmod(v1 / DATASET, stat.S_IWRITE | stat.S_IREAD)
        (v1 / DATASET).write_bytes((v1 / DATASET).read_bytes().replace(b'"ballot_count":5', b'"ballot_count":4'))

        with pytest.raises(ReleaseRefused) as refused:
            self.release(engine, sealed["election_id"], keys, results_keys, releases_dir)

        assert refused.value.code == "release_history_invalid"
        assert not (v1.parent / "v2").exists()

    def test_a_published_key_that_does_not_match_releases_nothing(
        self, engine, db_session, sealed, results_keys, releases_dir, keys, tmp_path
    ) -> None:
        """SR-18: if the published key is not the signer's, the read-back check fails and the folder is removed."""
        other = make_keys(tmp_path / "other")

        with pytest.raises(ReleaseRefused) as refused:
            self.release(engine, sealed["election_id"], keys, results_keys, releases_dir, published=other["private"].public_key())

        assert refused.value.code == "signature_check_failed"
        assert list((releases_dir / str(sealed["election_id"])).iterdir()) == []

    def test_missing_keys_stop_the_release(self, engine, db_session, sealed, releases_dir, monkeypatch, tmp_path, capsys) -> None:
        """SR-18: no results key: keys_missing, nothing counted or released, and the refusal is audited."""
        monkeypatch.setattr(release_results, "engine", engine)
        monkeypatch.setattr(settings, "results_private_key", tmp_path / "none.pem")

        assert release_results.main(["--election", str(sealed["election_id"])]) == 1

        assert "REFUSED: keys_missing (results private key (none.pem)" in capsys.readouterr().out
        assert not releases_dir.exists()
        assert [e.reason for e in self.events(db_session, "RESULT_RELEASE_REFUSED")] == ["keys_missing"]
        assert self.events(db_session, "COUNT_STARTED") == []

    # -- the release's contents --

    def test_the_release_folder_holds_no_key_or_fingerprint(self, engine, client, sealed, results_keys, releases_dir, keys) -> None:
        """SR-18: no PEM key anywhere in the folder; VERIFY.txt has neither the key nor the fingerprint, only the steps."""
        folder = self.released(engine, sealed["election_id"], keys, results_keys, releases_dir)
        pem, fingerprint = self.public_pem(client)
        key_body = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
        instructions = (folder / INSTRUCTIONS).read_text(encoding="utf-8")

        for path in folder.iterdir():
            content = path.read_bytes()
            assert b"-----BEGIN" not in content and key_body.encode() not in content, path.name
        assert fingerprint not in instructions and fingerprint.upper() not in instructions
        assert "/api/public/results-key" in instructions and "verify_release.py" in instructions and "openssl pkeyutl" in instructions

    def test_the_dataset_is_canonical_and_holds_totals_only(self, engine, db_session, sealed, results_keys, releases_dir, keys) -> None:
        """SR-18: the same inputs give the same bytes; the dataset has its fixed fields and no ballot, ranking or token."""
        result = self.count(engine, keys, sealed["election_id"])
        inputs = {
            "release_version": 3,
            "previous_release_sha256": "a" * 64,
            "generated_at": datetime(2027, 5, 15, 18, 0, tzinfo=UTC),
            "signing_key_fingerprint": key_fingerprint(results_keys["private"].public_key()),
        }

        data = build_dataset(result, **inputs)

        assert build_dataset(result, **inputs) == data
        dataset = json.loads(data)
        assert json.dumps(dataset, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() == data
        assert set(dataset) == {
            "schema", "election_id", "release_version", "previous_release_sha256", "generated_at",
            "final_chain_head", "ballot_count", "signing_key_fingerprint", "divisions",
        }
        assert (dataset["schema"], dataset["ballot_count"], dataset["generated_at"]) == (SCHEMA, 5, "2027-05-15T18:00:00+00:00")
        for entry in self.chain(db_session, sealed["election_id"]):
            assert str(entry.ballot_id).encode() not in data
        for forbidden in (b"ballot_id", b"ranked_candidate_ids", b"ballot_token", b"receipt", b"rankings"):
            assert forbidden not in data
        assert all(json.dumps(r).encode() not in data for r in sealed["rankings"])

    def test_no_route_returns_a_released_dataset(self, engine, client: TestClient, sealed, results_keys, releases_dir, keys) -> None:
        """SR-18: after a release, no GET route of the app returns its dataset or names its hash."""
        release = self.release(engine, sealed["election_id"], keys, results_keys, releases_dir)
        gets = [path for path, methods in api_routes() if "GET" in methods and "{" not in path]

        bodies = {path: client.get(path).text for path in gets}

        assert gets and {p: b for p, b in bodies.items() if SCHEMA in b or release.dataset_sha256 in b} == {}

    # -- the audit trail --

    def test_release_events_hold_allowed_fields_and_old_rows_still_verify(
        self, engine, db_session: Session, sealed, results_keys, releases_dir, keys
    ) -> None:
        """SR-18: RESULT_RELEASED with count and version only; format 1 and 2 rows written before still verify."""
        head = db_session.scalar(select(AuditLogEntry.hash).order_by(AuditLogEntry.id.desc()).limit(1))
        created = datetime(2026, 10, 1, tzinfo=UTC)
        v1_body = json.dumps({"created_at": created.isoformat(), "event_type": "ROLL_VERIFIED", "actor": "unknown", "details": {"records": 1}}, sort_keys=True)
        v1_hash = hashlib.sha256(head + v1_body.encode()).digest()
        v2_fields = {
            "format_version": 2, "created_at": created.isoformat(), "event_type": "ROLL_VERIFIED", "category": "configuration",
            "outcome": "success", "actor": "unknown", "role": "unknown", "request_id": "00000000-0000-4000-8000-000000000001",
            "batch_no": None, "count": 1, "reason": None,
        }
        v2_hash = hashlib.sha256(v1_hash + json.dumps(v2_fields, sort_keys=True, separators=(",", ":")).encode()).digest()
        db_session.add_all(
            [
                AuditLogEntry(created_at=created, event_type="ROLL_VERIFIED", actor="unknown", details={"records": 1}, format_version=1, prev_hash=head, hash=v1_hash),
                AuditLogEntry(
                    created_at=created, event_type="ROLL_VERIFIED", actor="unknown", category="configuration", outcome="success",
                    role="unknown", request_id=v2_fields["request_id"], count=1, format_version=2, prev_hash=v1_hash, hash=v2_hash,
                ),
            ]
        )
        db_session.commit()

        self.release(engine, sealed["election_id"], keys, results_keys, releases_dir)

        [released] = self.events(db_session, "RESULT_RELEASED")
        assert (released.category, released.outcome, released.actor, released.role, released.count, released.version) == (
            "ballot_box", "success", "script", "script", 5, 1
        )
        assert (released.reason, released.batch_no, released.details, released.format_version) == (None, None, None, AUDIT_FORMAT_CURRENT)
        assert verify_audit_chain(db_session)[1] is None
        old_v2 = db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.format_version == 2)).one()
        db_session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
        db_session.execute(text("UPDATE audit_log SET version = 7 WHERE id = :id"), {"id": old_v2.id})
        db_session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
        db_session.commit()
        assert verify_audit_chain(db_session)[1] == old_v2.id
