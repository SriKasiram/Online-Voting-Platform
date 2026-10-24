"""
The shared helpers from the clean-up: app/key_files.py (SR-02, SR-07, SR-11, SR-13, SR-16, SR-18,
SR-20), scripts/signing_keys.py and scripts/report.py. Each SR's own tests still cover its behaviour;
these pin down what the sharing must not change: the order of the key checks, the exact messages,
the exact report lines, and that app/ holds no private-key or signing code.
"""

import re
from pathlib import Path

import pytest

from app import key_files
from app.ballot_crypto import BallotKeyError, load_key
from app.config import BACKEND_DIR
from app.key_files import KEY_BYTES, KeyFileProblem, load_public_key_file, read_symmetric_key, verify_signature
from scripts.backup_common import BackupRefused, load_backup_key
from scripts.report import Check, exit_code, status_line, summary_line, tally, verdict_line
from scripts.signing_keys import load_or_create_key_pair, sign, write_key_pair, write_secret_key


@pytest.fixture
def readable_by_others(monkeypatch: pytest.MonkeyPatch) -> None:
    """A key file that group or others can read, as on POSIX, on any system."""
    monkeypatch.setattr(key_files, "readable_by_others", lambda path: True)


@pytest.fixture
def owner_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """A key file only its owner can read, on any system (a file a test writes is 0644 on Linux)."""
    monkeypatch.setattr(key_files, "readable_by_others", lambda path: False)


def test_symmetric_key_reasons(tmp_path: Path, owner_only) -> None:
    """SR-11, SR-20: a missing file, a wrong size, and a good 32-byte key."""
    with pytest.raises(KeyFileProblem) as missing:
        read_symmetric_key(tmp_path / "none.key")
    (tmp_path / "short.key").write_bytes(b"x" * 31)
    with pytest.raises(KeyFileProblem) as short:
        read_symmetric_key(tmp_path / "short.key")
    (tmp_path / "good.key").write_bytes(b"k" * KEY_BYTES)

    assert (missing.value.reason, short.value.reason, short.value.size) == ("missing", "wrong_size", 31)
    assert read_symmetric_key(tmp_path / "good.key") == b"k" * 32


def test_each_caller_keeps_its_order_of_checks(tmp_path: Path, readable_by_others) -> None:
    """SR-11 checks the permissions before the size; SR-20 the size first. Both orders are kept."""
    (tmp_path / "bad.key").write_bytes(b"x" * 31)

    with pytest.raises(KeyFileProblem) as ballot_order:
        read_symmetric_key(tmp_path / "bad.key")
    with pytest.raises(KeyFileProblem) as backup_order:
        read_symmetric_key(tmp_path / "bad.key", size_first=True)

    assert (ballot_order.value.reason, backup_order.value.reason) == ("readable_by_others", "wrong_size")


def test_the_ballot_key_messages_are_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-11: the same three messages as before the checks were shared."""
    path = tmp_path / "ballot.key"
    with pytest.raises(BallotKeyError, match=re.escape(f"No ballot key at {path}. Create it with: python -m scripts.gen_ballot_key")):
        load_key(path)
    path.write_bytes(b"x" * 16)
    # owner-only on every system, so the size check is reached (SR-11 checks the permissions first)
    monkeypatch.setattr(key_files, "readable_by_others", lambda p: False)
    with pytest.raises(BallotKeyError, match=re.escape(f"The ballot key {path} must be exactly 32 bytes (AES-256), not 16")):
        load_key(path)
    monkeypatch.setattr(key_files, "readable_by_others", lambda p: True)
    with pytest.raises(BallotKeyError, match=re.escape(f"The ballot key {path} can be read by other users. Run: chmod 600 {path}")):
        load_key(path)


def test_the_backup_key_refusals_are_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SR-20: the same codes and messages as before the checks were shared."""
    path = tmp_path / "backup.key"
    refusals = []
    for content, readable in ((None, False), (b"x" * 16, True), (b"k" * 32, True)):
        if content is not None:
            path.write_bytes(content)
        monkeypatch.setattr(key_files, "readable_by_others", lambda p, readable=readable: readable)
        with pytest.raises(BackupRefused) as refused:
            load_backup_key(path)
        refusals.append(str(refused.value))

    assert refusals == [
        f"backup_key_missing: no backup key at {path}. Create it with: python -m scripts.gen_backup_key",
        f"backup_key_invalid: {path} must be exactly 32 bytes (AES-256)",
        f"backup_key_invalid: {path} can be read by other users: chmod 600 it",
    ]


def test_key_writers_never_overwrite_without_force(tmp_path: Path) -> None:
    """SR-11, SR-13, SR-18, SR-20: the shared writers refuse to replace a key unless forced."""
    secret = write_secret_key(tmp_path / "a.key")
    first = secret.read_bytes()
    with pytest.raises(FileExistsError):
        write_secret_key(secret)
    write_secret_key(secret, force=True)
    private, public = write_key_pair(tmp_path / "p.pem", tmp_path / "p.pub.pem")
    with pytest.raises(FileExistsError):
        write_key_pair(private, public)

    assert len(first) == 32 and secret.read_bytes() != first
    assert load_public_key_file(public) is not None


def test_signing_and_verifying_meet_in_the_middle(tmp_path: Path) -> None:
    """SR-02, SR-07, SR-13, SR-16, SR-18: scripts sign, app verifies; any change to the bytes fails."""
    key = load_or_create_key_pair(tmp_path / "k.pem", tmp_path / "k.pub.pem")
    public = load_public_key_file(tmp_path / "k.pub.pem")
    signature = sign(key, b"evoting-test-v1\nmessage")

    assert verify_signature(public, signature, b"evoting-test-v1\nmessage")
    assert not verify_signature(public, signature, b"evoting-test-v1\nmessagE")
    assert not verify_signature(public, b"\x00" * 64, b"evoting-test-v1\nmessage")


def test_app_holds_no_private_key_or_signing_code() -> None:
    """SR-07, SR-13, SR-18: nothing under app/ imports the signing module or loads a private key."""
    banned = re.compile(r"signing_keys|Ed25519PrivateKey|load_pem_private_key|private_bytes|\.sign\(")
    hits = []
    for path in (BACKEND_DIR / "app").rglob("*.py"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            code = line.split("#")[0]
            if banned.search(code) and not code.strip().startswith(('"', "'")) and "signing live in" not in line:
                hits.append(f"{path.name}:{number}")

    assert hits == []


def test_report_lines_are_exactly_as_before() -> None:
    """SR-11, SR-12, SR-13, SR-16: the shared lines match the old f-strings character for character."""
    checks = [Check("a", "PASS", "fine"), Check("b", "FAIL", "broken"), Check("c", "SKIPPED", "no git")]

    assert status_line("PASS", "chain links") == "PASS     chain links"
    assert status_line("FAIL", "chain links", "broken_link") == "FAIL     chain links: broken_link"
    assert status_line("SKIPPED", "c", "no git") == "SKIPPED  c: no git"
    assert tally(checks) == (1, 1, 1)
    assert summary_line(checks) == "Summary: 1 passed, 1 failed, 1 skipped"
    assert verdict_line("SR-13 chain verification", True, 0) == "SR-13 chain verification: PASS"
    assert verdict_line("SR-13 chain verification", False, 2) == "SR-13 chain verification: FAIL (2 checks)"
    assert verdict_line("SR-16 audit verification", False) == "SR-16 audit verification: FAIL"
    assert (exit_code(True), exit_code(False)) == (0, 1)
