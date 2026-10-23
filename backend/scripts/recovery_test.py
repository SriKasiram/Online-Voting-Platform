"""
SR-20: the recovery test. Run quarterly and before each election, inside backend/:

    python -m scripts.recovery_test --reset-target

Takes a backup of the live database (label recovery_test), then starts a monotonic timer, restores
the backup into RESTORE_DATABASE_URL and checks the restored copy:
  a. time: the restore and the checks finish within RESTORE_TIME_LIMIT_SECONDS (30 minutes);
  b. zero_loss: every election with chain entries passes the SR-13 chain check on the restored
     database, against the live signed checkpoints (CHECKPOINT_DIR), and the restored database
     holds exactly the manifest's ballot_count ballots;
  c. reconciliation: per election, used ballot tokens = ballots = electors marked voted, and every
     used token still has its receipt hash (the hash of the confirmation reference the voter holds).
Every check reads totals per election only: nothing joins the identity side to the ballot side
(SR-12). --reset-target first empties the target, only if it is not the live database and its
name ends with _restore. Exit code 0 only if all three checks pass. Writes no audit event.
"""

import argparse
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session

from app.ballot_chain import checkpoint_file, load_checkpoint_public_key, verify_chain
from app.config import settings
from app.db import engine
from app.house_count import read_only_snapshot
from scripts.backup_common import BackupRefused, check_target, load_backup_key, reset_target
from scripts.backup_db import Backup, take_backup
from scripts.restore_db import restore


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class Report:
    backup: Backup | None
    checks: list[Check]
    seconds: float

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(check.passed for check in self.checks)


def per_election(session: Session, sql: str) -> dict[uuid.UUID, int]:
    # SR-20: one table per query, grouped by election: totals only, never a join across the sides
    return {row[0]: row[1] for row in session.execute(text(sql))}


def zero_loss(session: Session, manifest: dict, public_key: Ed25519PublicKey | None) -> Check:
    """SR-20 check b: the restored chains verify against the live signed checkpoints, and no ballot is missing."""
    problems = []
    elections = sorted(session.scalars(text("SELECT DISTINCT election_id FROM ballot_chain")), key=str)
    if elections and public_key is None:
        problems.append("the checkpoint public key is missing, so the chains cannot be checked")
    else:
        for election_id in elections:
            reasons = verify_chain(session, election_id, public_key, checkpoint_file(election_id))
            if reasons:
                problems.append(f"election {election_id}: {', '.join(reasons)}")
    ballots = session.scalar(text("SELECT count(*) FROM ballots"))
    if ballots != manifest["ballot_count"]:
        problems.append(f"{ballots} ballots restored, the backup holds {manifest['ballot_count']}")
    if problems:
        return Check("zero_loss", False, "; ".join(problems))
    return Check("zero_loss", True, f"{ballots} ballots restored of {manifest['ballot_count']}; {len(elections)} chain(s) verified")


def reconciliation(session: Session) -> Check:
    """SR-20 check c: per election, used tokens = ballots = electors marked voted, and every used token has its receipt hash."""
    used = per_election(session, "SELECT election_id, count(*) FROM ballot_tokens WHERE consumed GROUP BY election_id")
    ballots = per_election(session, "SELECT election_id, count(*) FROM ballots GROUP BY election_id")
    voted = per_election(session, "SELECT election_id, count(*) FROM voter_participation WHERE state = 'voted' GROUP BY election_id")
    no_receipt = per_election(
        session, "SELECT election_id, count(*) FROM ballot_tokens WHERE consumed AND receipt_hash IS NULL GROUP BY election_id"
    )
    problems = []
    for election_id in sorted(set(used) | set(ballots) | set(voted) | set(no_receipt), key=str):
        totals = (used.get(election_id, 0), ballots.get(election_id, 0), voted.get(election_id, 0))
        if len(set(totals)) != 1:
            problems.append(f"election {election_id}: {totals[0]} used tokens, {totals[1]} ballots, {totals[2]} voted")
        if no_receipt.get(election_id):
            problems.append(f"election {election_id}: {no_receipt[election_id]} used token(s) without a receipt hash")
    if problems:
        return Check("reconciliation", False, "; ".join(problems))
    total = sum(ballots.values())
    return Check("reconciliation", True, f"{total} ballots = used tokens = voted, every receipt hash present")


def run_checks(target_engine: Engine, manifest: dict, public_key: Ed25519PublicKey | None, started: float, limit: int) -> Report:
    """SR-20: checks b and c on the restored database, read only, then check a stops the timer."""
    with read_only_snapshot(target_engine) as session:
        checks = [zero_loss(session, manifest, public_key), reconciliation(session)]
    seconds = time.monotonic() - started
    timed = Check("time", seconds <= limit, f"restore and checks took {seconds:.2f} s, limit {limit} s")
    return Report(None, [timed, *checks], seconds)


def recovery_test(
    source_engine: Engine,
    key: bytes,
    backups_dir: Path,
    target_url: str,
    live_url: URL | str,
    public_key: Callable[[], Ed25519PublicKey | None],
    limit: int,
    reset: bool = False,
) -> Report:
    """SR-20: backup, timed restore and checks. BackupRefused if the target or the backup is refused."""
    target = check_target(target_url, live_url)  # SR-20: refused before any backup is taken
    if reset:
        reset_target(target_url, live_url)
    backup = take_backup(source_engine, key, backups_dir, "recovery_test")
    started = time.monotonic()
    restore(backup.folder, target_url, live_url, key)
    target_engine = create_engine(target, hide_parameters=True)
    try:
        report = run_checks(target_engine, backup.manifest, public_key(), started, limit)
    finally:
        target_engine.dispose()
    return Report(backup, report.checks, report.seconds)


def live_public_key() -> Ed25519PublicKey | None:
    # SR-20: only needed when there are chains to check; zero_loss fails if it is needed and missing
    path = settings.backend_path(settings.checkpoint_public_key)
    return load_checkpoint_public_key(path) if path.is_file() else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-20: back up, restore into the restore database, and check nothing was lost")
    parser.add_argument("--reset-target", action="store_true", help="empty the restore database first (its name must end with _restore)")
    args = parser.parse_args(argv)
    print("SR-20 recovery test")
    began = time.monotonic()
    try:
        report = recovery_test(
            engine,
            load_backup_key(settings.backend_path(settings.backup_key_file)),
            settings.backend_path(settings.backups_dir),
            settings.restore_database_url.get_secret_value(),
            settings.database_url(),
            live_public_key,
            settings.restore_time_limit_seconds,
            reset=args.reset_target,
        )
    except BackupRefused as refused:
        print(f"REFUSED: {refused}")
        print("FAIL: the recovery test did not run to the end")
        return 1
    manifest = report.backup.manifest
    print(f"Backup {manifest['backup_id']} ({manifest['label']}, revision {manifest['alembic_revision']}) in {report.backup.folder}")
    for check in report.checks:
        print(f"  {check.name}: {'PASS' if check.passed else 'FAIL'}: {check.detail}")
    print(f"Restore and checks: {report.seconds:.2f} s. Total time, backup included: {time.monotonic() - began:.2f} s")
    print("PASS: all checks passed" if report.passed else "FAIL: at least one check failed")
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
