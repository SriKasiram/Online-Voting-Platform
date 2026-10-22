"""
SR-11: every stored ballot is AES-256-GCM encrypted, the API does not start without a usable
key, and the pre-release audit finds no plaintext ballot record.
"""

import json
import logging
import os
import shutil
import subprocess
import uuid
from contextlib import nullcontext
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.ballot_crypto import (
    DIVISION_FIELD,
    PAYLOAD_FIELDS,
    RANKING_FIELD,
    BallotDecryptionError,
    BallotKeyError,
    ballot_payload,
    decrypt_ballot,
    encrypt_ballot,
)
from app.config import settings
from app.main import app
from app.security import audit
from scripts import audit_ballots
from scripts.gen_ballot_key import generate_ballot_key

PAYLOAD = ballot_payload(7, [13, 11, 12])
BALLOT_ID, ELECTION_ID = uuid.uuid4(), uuid.uuid4()


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def flipped(blob: bytes, index: int) -> bytes:
    return blob[:index] + bytes([blob[index] ^ 0x01]) + blob[index + 1 :]


def cast_ballot(client: TestClient, make_voter, sign_in) -> list[int]:
    """SR-11: a real ballot through the API. Returns the ranking that was submitted."""
    sign_in(make_voter())
    ballot = client.get("/api/ballot").json()
    ranking = [c["id"] for c in reversed(ballot["candidates"])]
    response = client.post("/api/ballot/submit", json={"ballot_token": ballot["ballot_token"], "ranked_candidate_ids": ranking})
    assert response.status_code == 200
    return ranking


def readable_forms(ranking: list[int], division_id: int) -> list[bytes]:
    """SR-11: ways a ballot could appear as readable text. Single digits are not used: random bytes contain them."""
    return [
        json.dumps(ranking).encode(),
        json.dumps(ranking, separators=(",", ":")).encode(),
        canonical(ballot_payload(division_id, ranking)),
        *(field.encode() for field in PAYLOAD_FIELDS),
    ]


# ---------------------------------------------------------------
# The cipher
# ---------------------------------------------------------------


def test_encrypt_then_decrypt_returns_the_payload() -> None:
    """SR-11 test 1: decrypting what was encrypted gives back the exact payload."""
    assert decrypt_ballot(encrypt_ballot(PAYLOAD, BALLOT_ID, ELECTION_ID), BALLOT_ID, ELECTION_ID) == PAYLOAD


def test_same_payload_twice_gives_different_ciphertexts() -> None:
    """SR-11 test 2: a fresh random nonce every time, so equal ballots never look equal when stored."""
    first, second = (encrypt_ballot(PAYLOAD, BALLOT_ID, ELECTION_ID) for _ in range(2))

    assert first != second
    assert first[1:13] != second[1:13]


def test_stored_format() -> None:
    """SR-11 test 3: version byte 0x01, then 12-byte nonce, ciphertext the size of the plaintext, and a 16-byte tag."""
    blob = encrypt_ballot(PAYLOAD, BALLOT_ID, ELECTION_ID)

    assert blob[0] == 0x01
    assert len(blob) == 1 + 12 + len(canonical(PAYLOAD)) + 16


@pytest.mark.parametrize("where", ["ciphertext", "tag"])
def test_modified_ciphertext_fails(where: str) -> None:
    """SR-11 test 4: one flipped bit in the ciphertext or its tag and the ballot no longer opens."""
    blob = encrypt_ballot(PAYLOAD, BALLOT_ID, ELECTION_ID)

    with pytest.raises(BallotDecryptionError, match="did not decrypt"):
        decrypt_ballot(flipped(blob, 13 if where == "ciphertext" else len(blob) - 1), BALLOT_ID, ELECTION_ID)


def test_modified_nonce_fails() -> None:
    """SR-11 test 5: a changed nonce fails too."""
    blob = encrypt_ballot(PAYLOAD, BALLOT_ID, ELECTION_ID)

    with pytest.raises(BallotDecryptionError, match="did not decrypt"):
        decrypt_ballot(flipped(blob, 5), BALLOT_ID, ELECTION_ID)


@pytest.mark.parametrize(
    ("make_blob", "message"),
    [
        (lambda blob: b"\x02" + blob[1:], "^unknown ballot format version$"),
        (lambda blob: blob[:28], "too short"),
        (lambda blob: b"", "too short"),
    ],
    ids=["unknown-version", "one-byte-short", "empty"],
)
def test_unknown_version_or_short_blob_fails_clearly(make_blob, message: str) -> None:
    """SR-11 test 6: an unknown version byte or a blob shorter than version + nonce + tag gets a clear error."""
    blob = encrypt_ballot(PAYLOAD, BALLOT_ID, ELECTION_ID)

    with pytest.raises(BallotDecryptionError, match=message):
        decrypt_ballot(make_blob(blob), BALLOT_ID, ELECTION_ID)


@pytest.mark.parametrize("moved_to", ["another ballot", "another election"])
def test_ciphertext_moved_to_another_row_fails(moved_to: str) -> None:
    """SR-11 test 7: the ballot and election ids are associated data, so a copied ciphertext does not open."""
    blob = encrypt_ballot(PAYLOAD, BALLOT_ID, ELECTION_ID)
    ballot_id, election_id = (uuid.uuid4(), ELECTION_ID) if moved_to == "another ballot" else (BALLOT_ID, uuid.uuid4())

    with pytest.raises(BallotDecryptionError):
        decrypt_ballot(blob, ballot_id, election_id)


def test_wrong_key_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-11 test 8: another 32-byte key cannot open the ballot."""
    blob = encrypt_ballot(PAYLOAD, BALLOT_ID, ELECTION_ID)
    monkeypatch.setattr(settings, "ballot_key_file", generate_ballot_key(tmp_path / "other.key"))

    with pytest.raises(BallotDecryptionError):
        decrypt_ballot(blob, BALLOT_ID, ELECTION_ID)


# ---------------------------------------------------------------
# The key at start-up
# ---------------------------------------------------------------


def start_api() -> None:
    """The API's real start-up (its lifespan), as uvicorn runs it."""
    with TestClient(app):
        pass


POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="Windows has no group or other permission bits")


@pytest.mark.parametrize(
    ("problem", "message"),
    [
        pytest.param("missing", "No ballot key", id="missing"),
        pytest.param("31 bytes", "exactly 32 bytes", id="too-short"),
        pytest.param("33 bytes", "exactly 32 bytes", id="too-long"),
        pytest.param("group can read", "can be read by other users", id="group-readable", marks=POSIX_ONLY),
        pytest.param("others can read", "can be read by other users", id="others-readable", marks=POSIX_ONLY),
    ],
)
def test_api_refuses_to_start_without_a_usable_key(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, problem: str, message: str
) -> None:
    """SR-11 test 9: missing, wrong-length or (POSIX) group- or other-readable keys stop the API from starting."""
    key = tmp_path / "ballot.key"
    if problem != "missing":
        generate_ballot_key(key)
    if problem in ("31 bytes", "33 bytes"):
        key.write_bytes(os.urandom(31 if problem == "31 bytes" else 33))
        os.chmod(key, 0o600)
    if problem == "group can read":
        os.chmod(key, 0o640)
    if problem == "others can read":
        os.chmod(key, 0o604)
    monkeypatch.setattr(settings, "ballot_key_file", key)

    with pytest.raises(BallotKeyError, match=message):
        start_api()


# ---------------------------------------------------------------
# A real ballot, end to end
# ---------------------------------------------------------------


def test_submitted_ballot_is_stored_encrypted(
    client: TestClient, db_session: Session, election, make_voter, sign_in
) -> None:
    """SR-11 test 10: the raw row holds unreadable bytes only, and decrypt_ballot gives back what was cast."""
    ranking = cast_ballot(client, make_voter, sign_in)
    division_id = election.divisions["Northgate"].id

    ballot_id, election_id, blob = db_session.execute(text("SELECT id, election_id, encrypted_payload FROM ballots")).one()

    assert isinstance(blob, bytes)
    for readable in readable_forms(ranking, division_id):
        assert readable not in blob
    with pytest.raises((UnicodeDecodeError, ValueError)):
        json.loads(blob)
    assert decrypt_ballot(blob, ballot_id, election_id) == {DIVISION_FIELD: division_id, RANKING_FIELD: ranking}


def test_no_ballot_content_in_audit_log_or_logs(
    client: TestClient, db_session: Session, election, make_voter, sign_in, caplog: pytest.LogCaptureFixture
) -> None:
    """SR-11 test 11: after a submission neither the audit log nor any log line holds the ballot."""
    caplog.set_level(logging.DEBUG)
    ranking = cast_ballot(client, make_voter, sign_in)

    audit_text = " ".join(
        db_session.scalars(text("SELECT event_type || ' ' || actor || ' ' || details::text FROM audit_log")).all()
    )
    assert "BALLOT_ACCEPTED" in audit_text
    for readable in readable_forms(ranking, election.divisions["Northgate"].id):
        assert readable.decode() not in audit_text
        assert readable.decode() not in caplog.text


def test_malformed_submission_is_not_echoed_back(client: TestClient, make_voter, sign_in) -> None:
    """SR-11 test 12: a 422 for a malformed ballot says where it failed, but never repeats what was sent."""
    sign_in(make_voter())
    token = client.get("/api/ballot").json()["ballot_token"]

    response = client.post("/api/ballot/submit", json={"ballot_token": token, "ranked_candidate_ids": [101, "TOP-SECRET-PICK"]})

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "ranked_candidate_ids", 1]
    assert "TOP-SECRET-PICK" not in response.text and "101" not in response.text and token not in response.text


# ---------------------------------------------------------------
# The pre-release audit
# ---------------------------------------------------------------


def statuses(checks: list[audit_ballots.Check]) -> dict[str, str]:
    return {check.name: check.status for check in checks}


def run_main(db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
    """SR-11: the script's own main(), against the test database and with log files looked for in tmp_path."""
    monkeypatch.setattr(audit_ballots, "SessionLocal", lambda: nullcontext(db_session))
    monkeypatch.setattr(audit_ballots, "PROJECT_DIR", tmp_path)
    return audit_ballots.main()


def test_audit_passes_on_a_clean_database_after_a_submission(
    client: TestClient, db_session: Session, make_voter, sign_in, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """SR-11 test 13: a real encrypted ballot passes every check; outside a git repository the git check is SKIPPED."""
    cast_ballot(client, make_voter, sign_in)

    checks = statuses(audit_ballots.run_audit(db_session, tmp_path))
    exit_code = run_main(db_session, tmp_path, monkeypatch)

    assert checks.pop("d. key not in git") == "SKIPPED"
    assert set(checks.values()) == {"PASS"}
    output = capsys.readouterr().out
    assert exit_code == 0 and "Result: PASS (exit code 0)" in output and "WARNING" in output
    assert "PASS     a. ballot records: 1 ballot(s)" in output


def test_audit_fails_on_a_plaintext_row(
    client: TestClient, db_session: Session, election, make_voter, sign_in, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """SR-11 test 14: a plaintext JSON row inserted directly fails check a, by id only, and the script exits 1."""
    cast_ballot(client, make_voter, sign_in)
    fake_id = uuid.uuid4()
    plaintext = canonical(ballot_payload(election.divisions["Northgate"].id, [3, 1, 2]))
    db_session.execute(
        text("INSERT INTO ballots (id, election_id, encrypted_payload) VALUES (:id, :election, :blob)"),
        {"id": fake_id, "election": election.election.id, "blob": plaintext},
    )

    check = audit_ballots.check_ballot_records(db_session)
    exit_code = run_main(db_session, tmp_path, monkeypatch)

    assert check.status == "FAIL"
    assert check.reason == f"1 of 2 plaintext or invalid: {fake_id} (readable JSON)"
    output = capsys.readouterr().out
    assert exit_code == 1 and "Result: FAIL (exit code 1)" in output
    assert plaintext.decode() not in output and "[3,1,2]" not in output


@pytest.mark.parametrize("problem", ["missing", "wrong length"])
def test_audit_fails_without_a_usable_key(
    db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, problem: str
) -> None:
    """SR-11 test 15: a missing key file, or one that is not 32 bytes, fails check d and the script exits 1."""
    key = tmp_path / "ballot.key"
    if problem == "wrong length":
        key.write_bytes(os.urandom(16))
    monkeypatch.setattr(settings, "ballot_key_file", key)

    assert audit_ballots.check_key_file(key).status == "FAIL"
    assert run_main(db_session, tmp_path, monkeypatch) == 1


def test_audit_fails_on_a_legacy_plaintext_column(db_session: Session) -> None:
    """SR-11 test 16: an old plaintext column on ballots fails check b (added and dropped inside the test)."""
    db_session.execute(text("ALTER TABLE ballots ADD COLUMN ciphertext bytea"))
    try:
        check = audit_ballots.check_ballot_columns(db_session)
    finally:
        db_session.execute(text("ALTER TABLE ballots DROP COLUMN ciphertext"))

    assert check.status == "FAIL"
    assert "old plaintext columns: ciphertext" in check.reason
    assert audit_ballots.check_ballot_columns(db_session).status == "PASS"


def test_audit_fails_when_a_log_names_a_ballot_field(db_session: Session, tmp_path: Path) -> None:
    """SR-11 test 17: a ballot field name in the audit log, or in a log file, fails check e."""
    assert audit_ballots.check_logs(db_session, tmp_path).status == "PASS"

    (tmp_path / "api.log").write_text(f"request body: {{'{RANKING_FIELD}': [3, 1, 2]}}", encoding="utf-8")
    assert audit_ballots.check_logs(db_session, tmp_path).status == "FAIL"

    (tmp_path / "api.log").unlink()
    audit(db_session, "TEST_EVENT", actor="unknown", note=DIVISION_FIELD)
    assert audit_ballots.check_logs(db_session, tmp_path).status == "FAIL"


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_audit_git_check(tmp_path: Path) -> None:
    """SR-11 test 18: an ignored, untracked key passes; a tracked key fails; outside a repository it is SKIPPED."""
    outside = generate_ballot_key(tmp_path / "loose" / "ballot.key")
    assert audit_ballots.check_key_in_git(outside).status == "SKIPPED"

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "--template=", str(repo)], check=True)
    (repo / ".gitignore").write_text("keys/\n", encoding="utf-8")
    key = generate_ballot_key(repo / "keys" / "ballot.key")
    assert audit_ballots.check_key_in_git(key).status == "PASS"

    subprocess.run(["git", "add", "-f", "keys/ballot.key"], cwd=repo, check=True)
    tracked = audit_ballots.check_key_in_git(key)
    assert tracked.status == "FAIL" and "tracked by git" in tracked.reason
