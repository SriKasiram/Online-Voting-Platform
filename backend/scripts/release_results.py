"""
SR-18: releases an election's House results, signed with the dedicated results key. Run inside
backend/, after polls close and the final seal:

    python -m scripts.release_results --election <election id>

The only way results leave the platform. In order, and any failure stops it with a reason code and
exit code 1:
  a. a fresh SR-17 count in this same run (every SR-17 check applies); a result file on disk is
     never signed, so nothing edited after a count can be released
  b. the release history RELEASES_DIR/<election>/releases.jsonl must hold: every logged version's
     result.json still has its logged SHA-256, and each names the one before (release_history_invalid)
  c. RELEASES_DIR/<election>/v<N>/ is created new, never reused (version_exists)
  d. result.json (the exact canonical bytes) and result.json.sig (the raw 64-byte Ed25519 signature
     over exactly those bytes, with no domain tag: the key signs nothing else)
  e. both files are read back and checked with the published public key; on failure the folder is
     deleted, because it was never released (signature_check_failed)
  f. VERIFY.txt: how a recipient checks it. It holds neither the key nor its fingerprint, which a
     recipient must get from the official page, not from the release itself
  g. the three files made read-only, then one line appended to releases.jsonl
  h. the RESULT_RELEASED audit entry (SR-16), and the version, folder and dataset SHA-256 printed

A correction is always a new version that names the previous one; an existing release is never
changed. The release folder never holds a key.
"""

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app import security
from app.audit_events import FAILURE, SCRIPT, SUCCESS
from app.ballot_chain import checkpoint_file, load_checkpoint_public_key
from app.ballot_crypto import BallotKeyError, load_key
from app.config import settings
from app.db import engine
from app.house_count import CountRefused, run_count
from app.result_dataset import build_dataset, key_fingerprint, load_results_public_key
from app.roll_signing import verify_signature
from app.security import audit
# SR-18: the SR-13 Ed25519 private key loader, used here for the dedicated results key
from scripts.seal_ballots import load_private_key

DATASET = "result.json"
SIGNATURE = "result.json.sig"
INSTRUCTIONS = "VERIFY.txt"
LOG = "releases.jsonl"
LOG_FIELDS = {"version", "dataset_sha256", "previous_release_sha256", "generated_at"}


class ReleaseRefused(Exception):
    """SR-18: nothing was released. `code` is an SR-16 reason code."""

    def __init__(self, code: str, details: list[str] | None = None, version: int | None = None, ballots: int | None = None) -> None:
        super().__init__(code + (f" ({', '.join(details)})" if details else ""))
        self.code = code
        self.details = details or []
        self.version = version
        self.ballots = ballots


@dataclass(frozen=True)
class Release:
    version: int
    folder: Path
    dataset_sha256: str
    previous_release_sha256: str | None
    ballot_count: int


def releases_of(releases_dir: Path, election_id: uuid.UUID) -> Path:
    return releases_dir / str(election_id)


def read_history(folder: Path) -> list[dict]:
    """SR-18 step b: the logged releases, each checked against its folder and the one before."""
    log = folder / LOG
    if not log.is_file():
        return []
    history: list[dict] = []
    previous = None
    for number, line in enumerate(log.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            entry = json.loads(line)
            dataset = folder / f"v{number}" / DATASET
            intact = (
                set(entry) == LOG_FIELDS
                and entry["version"] == number
                and entry["previous_release_sha256"] == previous
                and dataset.is_file()
                and hashlib.sha256(dataset.read_bytes()).hexdigest() == entry["dataset_sha256"]
            )
        except (ValueError, TypeError, AttributeError, OSError):
            intact = False
        if not intact:
            raise ReleaseRefused("release_history_invalid", [f"version {number}"])
        history.append(entry)
        previous = entry["dataset_sha256"]
    return history


def verify_instructions(version: int) -> str:
    """SR-18 step f: deliberately without the key or its fingerprint, which must come from the official page."""
    return f"""House result release, version {version}

Files:
  result.json      the result dataset: these exact bytes were signed
  result.json.sig  the raw 64-byte Ed25519 signature over result.json

To check that this release is genuine and unchanged:

1. Get the results public key from the official page, never from this folder or from whoever
   sent it. In the prototype the official page is
   https://localhost:8443/api/public/results-key
   It returns the key (public_key_pem) and its fingerprint (fingerprint_sha256). Save
   public_key_pem as results_public.pem.

2. Compare that fingerprint with the one published through another official channel.
   The fingerprint is the SHA-256 of the raw 32-byte public key.

3. Verify with the recipient's script (Python 3 and the cryptography package only):
   python verify_release.py --dataset result.json --signature result.json.sig --public-key results_public.pem --expected-fingerprint <fingerprint>
   It must print VALID. It also checks that the dataset names the same signing key.

   Or with OpenSSL 3.0 or later:
   openssl pkeyutl -verify -pubin -inkey results_public.pem -rawin -in result.json -sigfile result.json.sig
   It must print "Signature Verified Successfully".

A release is never changed. A correction is a new version whose previous_release_sha256 is
the SHA-256 of this result.json.
"""


def make_read_only(path: Path) -> None:
    # SR-18: a released file must not be edited by accident; on Windows this sets the read-only attribute
    os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def remove_unreleased(folder: Path) -> None:
    """SR-18: a version folder that failed a step was never released, so it must not stay behind."""

    def writable_then_retry(function, path, _error):
        # A file already made read-only cannot be deleted on Windows until it is writable again
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        function(path)

    if folder.exists():
        shutil.rmtree(folder, onexc=writable_then_retry)


def release(
    db_engine: Engine,
    election_id: uuid.UUID,
    private_key: Ed25519PrivateKey,
    published_key: Ed25519PublicKey,
    checkpoint_key: Ed25519PublicKey,
    checkpoint_path: Path,
    releases_dir: Path,
) -> Release:
    """SR-18: steps a to g. Raises ReleaseRefused, leaving no new folder and no log line, on any failure."""
    # a. a fresh count in this run: never a result read from disk
    try:
        result = run_count(db_engine, election_id, checkpoint_key, checkpoint_path)
    except CountRefused as refused:
        raise ReleaseRefused(refused.code, refused.details) from None
    ballots = result["ballots_counted"]
    folder = releases_of(releases_dir, election_id)
    # b. the history this release will extend
    try:
        history = read_history(folder)
    except ReleaseRefused as refused:
        refused.ballots = ballots
        raise
    version = len(history) + 1
    previous = history[-1]["dataset_sha256"] if history else None
    # c. a new folder, never an existing one
    target = folder / f"v{version}"
    folder.mkdir(parents=True, exist_ok=True)
    try:
        target.mkdir(exist_ok=False)
    except FileExistsError:
        raise ReleaseRefused("version_exists", version=version, ballots=ballots) from None
    try:
        generated_at = security.utc_now()
        dataset = build_dataset(
            result,
            release_version=version,
            previous_release_sha256=previous,
            generated_at=generated_at,
            # SR-18: the key that really signs, so a mismatched published key fails step e
            signing_key_fingerprint=key_fingerprint(private_key.public_key()),
        )
        # d. the exact bytes, in binary mode, and the raw signature over exactly those bytes
        (target / DATASET).write_bytes(dataset)
        (target / SIGNATURE).write_bytes(private_key.sign(dataset))
        # e. read back and checked as a recipient would, with the published key
        written = (target / DATASET).read_bytes()
        if written != dataset or not verify_signature(published_key, (target / SIGNATURE).read_bytes(), written):
            raise ReleaseRefused("signature_check_failed", version=version, ballots=ballots)
        # f. how to verify, without the key or fingerprint
        (target / INSTRUCTIONS).write_text(verify_instructions(version), encoding="utf-8", newline="\n")
        # g. read-only, then logged: a release exists only once its line is in the log
        for name in (DATASET, SIGNATURE, INSTRUCTIONS):
            make_read_only(target / name)
    except BaseException:
        remove_unreleased(target)
        raise
    dataset_sha256 = hashlib.sha256(dataset).hexdigest()
    entry = {"version": version, "dataset_sha256": dataset_sha256, "previous_release_sha256": previous, "generated_at": generated_at.isoformat()}
    with (folder / LOG).open("a", encoding="utf-8", newline="\n") as log:
        log.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
    return Release(version, target, dataset_sha256, previous, ballots)


def release_results(
    db_engine: Engine,
    election_id: uuid.UUID,
    private_key: Ed25519PrivateKey,
    published_key: Ed25519PublicKey,
    checkpoint_key: Ed25519PublicKey,
    checkpoint_path: Path,
    releases_dir: Path,
) -> Release:
    """SR-18: the release with its SR-16 entry: RESULT_RELEASED, or RESULT_RELEASE_REFUSED and re-raise."""
    try:
        done = release(db_engine, election_id, private_key, published_key, checkpoint_key, checkpoint_path, releases_dir)
    except ReleaseRefused as refused:
        record_refusal(db_engine, refused)
        raise
    with Session(db_engine) as db:
        # SR-18 h: only the outcome, the ballot count and the version; never the dataset, its hash or a key
        audit(db, "RESULT_RELEASED", outcome=SUCCESS, actor=SCRIPT, role=SCRIPT, count=done.ballot_count, version=done.version)
        db.commit()
    return done


def record_refusal(db_engine: Engine, refused: ReleaseRefused) -> None:
    with Session(db_engine) as db:
        audit(
            db,
            "RESULT_RELEASE_REFUSED",
            outcome=FAILURE,
            actor=SCRIPT,
            role=SCRIPT,
            reason=refused.code,
            count=refused.ballots,
            version=refused.version,
        )
        db.commit()


def load_keys() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, Ed25519PublicKey]:
    """SR-18: every key the release needs, or ReleaseRefused("keys_missing") naming the missing one."""
    try:
        load_key(settings.ballot_key_file)
    except BallotKeyError as problem:
        raise ReleaseRefused("keys_missing", [f"ballot key: {problem}"]) from None
    paths = {
        "checkpoint public key": settings.backend_path(settings.checkpoint_public_key),
        "results private key": settings.backend_path(settings.results_private_key),
        "results public key": settings.backend_path(settings.results_public_key),
    }
    missing = [f"{name} ({path.name})" for name, path in paths.items() if not path.is_file()]
    if missing:
        raise ReleaseRefused("keys_missing", missing)
    return (
        load_private_key(paths["results private key"]),
        load_results_public_key(paths["results public key"]),
        load_checkpoint_public_key(paths["checkpoint public key"]),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-18: release an election's House results, signed")
    parser.add_argument("--election", type=uuid.UUID, required=True, help="the election id")
    args = parser.parse_args(argv)
    print("SR-18 House result release")
    try:
        try:
            private_key, published_key, checkpoint_key = load_keys()
        except ReleaseRefused as refused:
            record_refusal(engine, refused)
            raise
        done = release_results(
            engine,
            args.election,
            private_key,
            published_key,
            checkpoint_key,
            checkpoint_file(args.election),
            settings.backend_path(settings.releases_dir),
        )
    except ReleaseRefused as refused:
        print(f"REFUSED: {refused}")
        print("Nothing was released. Investigate the cause: no check can be skipped.")
        return 1
    print(f"Released version {done.version} in {done.folder}")
    print(f"Dataset SHA-256: {done.dataset_sha256}")
    if done.previous_release_sha256:
        print(f"Previous release SHA-256: {done.previous_release_sha256}")
    print("Recipients verify it with the key from /api/public/results-key (see VERIFY.txt).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
