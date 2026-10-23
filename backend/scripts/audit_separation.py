"""
SR-12: the separation audit, run before each election. Inside backend/:

    python -m scripts.audit_separation [--file PATH ...]

Checks the schema, the data, the logs and any backup or export files given with --file, and
confirms that nothing persistent links an elector on the identity side to a ballot on the ballot
side (app/stores.py). Prints one PASS, FAIL or SKIPPED line per check, then a summary, and exits
with code 1 if any check fails. It prints only counts and table, column or file names: never a
ballot, a full token hash, a receipt or anything about an elector.
"""

import argparse
import hashlib
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import PROJECT_DIR, settings
from app.db import SessionLocal
from app.stores import BALLOT_TABLES, IDENTITY_TABLES, NOT_APPLICATION_DATA

Status = Literal["PASS", "FAIL", "SKIPPED"]

# SR-12: the three shapes a ballot-side identifier takes. Text is scanned once per pattern and the
# matches are looked up in a set, never searched for one by one.
HEX64 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")  # token hashes
UUID_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])"
)  # ballot and token ids
# SR-14: receipt references (128 bits, 32 hex). The server keeps only their SHA-256, so a reference
# found in text is looked up by its hash: a leaked reference is caught, not just a leaked hash.
HEX32 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")

# SR-12: column names a ballot-side table may not have. "ip" counts only as a whole word of the name
# (ip, client_ip, ip_address), so that receipt_hash (SR-14) is not a false match.
FORBIDDEN_NAME_PARTS = ("elector", "roll", "user", "session", "agent")
TIME_TYPES = {"timestamp without time zone", "timestamp with time zone", "time without time zone", "time with time zone"}
# SR-13: an order number on the ballot side could replay the order ballots arrived in, so a column
# named as one (position, seq, batch...) is refused like a serial id. The one narrow exception:
# ballot_chain's own position and batch_no, which the seal script assigns in random ballot-id order
# within shuffled batches. Every other rule above still applies to ballot_chain.
ORDER_WORDS = {"position", "seq", "sequence", "ordinal", "counter", "batch"}
CHAIN_ORDER_COLUMNS = {("ballot_chain", "position"), ("ballot_chain", "batch_no")}

# SR-12: identity markers, for files that are not SQL dumps (exports). A file holding a ballot
# identifier and any of these fails:
# - any e-mail address (the platform stores none, so one in a ballot file came from elsewhere);
# - the username of any elector or staff account (accounts.username), matched as a whole word;
# - the primary key of any account or electoral roll entry (UUIDs).
# Small integers (division ids, candidate ids) are never markers: they would match everywhere.
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
WORD = re.compile(r"[A-Za-z0-9._]{3,32}")

SKIP_DIRS = {".git", "node_modules", ".venv", "dist", "__pycache__", ".pytest_cache"}


@dataclass
class Check:
    name: str
    status: Status
    reason: str


def identifiers_in(content: str) -> set[str]:
    """SR-12: every string in `content` shaped like a ballot-side identifier."""
    found = {match.lower() for match in HEX64.findall(content)}
    found |= {match.lower() for match in UUID_PATTERN.findall(content)}
    # SR-14: a reference shows up as the hash the server holds for it
    found |= {hashlib.sha256(match.lower().encode("ascii")).hexdigest() for match in HEX32.findall(content)}
    return found


def ballot_identifiers(db: Session) -> set[str]:
    """
    SR-12: ballot ids, token ids and token hashes, normalised like identifiers_in. SR-13: chain entry
    hashes. SR-14: receipt hashes, which also stand for the references themselves (see HEX32).
    """
    identifiers = {str(ballot_id).lower() for (ballot_id,) in db.execute(text("SELECT id FROM ballots"))}
    for token_id, token_hash, receipt_hash in db.execute(text("SELECT id, token_hash, receipt_hash FROM ballot_tokens")):
        identifiers |= {str(token_id).lower(), token_hash.lower()}
        if receipt_hash:
            identifiers.add(receipt_hash.lower())
    # SR-13: a chain entry hash points at one ballot too, so it may not appear on the identity side either
    identifiers |= {entry_hash.lower() for (entry_hash,) in db.execute(text("SELECT entry_hash FROM ballot_chain"))}
    return identifiers


def check_foreign_keys(db: Session) -> Check:
    """SR-12 (a): every table has a side, and no foreign key joins the two sides in either direction."""
    name = "a. schema, foreign keys"
    tables = set(db.scalars(text("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")))
    unclassified = sorted(tables - IDENTITY_TABLES - BALLOT_TABLES - NOT_APPLICATION_DATA)
    if unclassified:
        return Check(name, "FAIL", f"table(s) on neither side: {', '.join(unclassified)} (add them to app/stores.py)")
    links = db.execute(
        text(
            "SELECT src.relname, dst.relname FROM pg_constraint c "
            "JOIN pg_class src ON src.oid = c.conrelid JOIN pg_class dst ON dst.oid = c.confrelid "
            "JOIN pg_namespace n ON n.oid = src.relnamespace "
            "WHERE c.contype = 'f' AND n.nspname = current_schema()"
        )
    ).all()
    crossing = sorted(
        f"{source} -> {target}"
        for source, target in links
        if (source in BALLOT_TABLES and target in IDENTITY_TABLES) or (source in IDENTITY_TABLES and target in BALLOT_TABLES)
    )
    if crossing:
        return Check(name, "FAIL", f"foreign key(s) between the sides: {', '.join(crossing)}")
    return Check(name, "PASS", f"no foreign key between the {len(BALLOT_TABLES)} ballot-side and {len(IDENTITY_TABLES)} identity-side tables")


def forbidden_name(column: str) -> bool:
    lowered = column.lower()
    words = lowered.split("_")
    return any(part in lowered for part in FORBIDDEN_NAME_PARTS) or any(
        word == "ip" or word.startswith("ipaddr") or word in ("ipv4", "ipv6") for word in words
    )


def check_ballot_columns(db: Session) -> Check:
    """SR-12 (b): ballot-side columns name no elector, roll, user, session, IP or agent, hold no time, and none is serial."""
    name = "b. schema, ballot-side columns"
    problems: list[str] = []
    for table in sorted(BALLOT_TABLES):
        columns = db.execute(
            text(
                "SELECT column_name, data_type, column_default, is_identity FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = :table"
            ),
            {"table": table},
        ).all()
        for column, data_type, default, identity in columns:
            if forbidden_name(column):
                problems.append(f"{table}.{column} (identity-like name)")
            if data_type in TIME_TYPES:
                problems.append(f"{table}.{column} ({data_type})")
            if identity == "YES" or (default or "").startswith("nextval("):
                problems.append(f"{table}.{column} (serial)")
            # SR-13: order numbers are refused too, except ballot_chain's position and batch_no
            if set(column.lower().split("_")) & ORDER_WORDS and (table, column) not in CHAIN_ORDER_COLUMNS:
                problems.append(f"{table}.{column} (order number)")
    if problems:
        return Check(name, "FAIL", "; ".join(problems))
    return Check(name, "PASS", f"{', '.join(sorted(BALLOT_TABLES))}: no identity-like names, no time columns, no serial ids")


def check_identity_tables(db: Session, identifiers: set[str]) -> Check:
    """SR-12 (c): no ballot id, token id, token hash or receipt appears anywhere on the identity side."""
    name = "c. identity-side data"
    rows = 0
    found: dict[str, int] = {}
    for table in sorted(IDENTITY_TABLES):
        for (row,) in db.execute(text(f'SELECT t::text FROM "{table}" AS t')):
            rows += 1
            hits = len(identifiers_in(row) & identifiers)
            if hits:
                found[table] = found.get(table, 0) + hits
    if found:
        return Check(name, "FAIL", "ballot identifiers found in: " + ", ".join(f"{t} ({n})" for t, n in found.items()))
    return Check(name, "PASS", f"{len(identifiers)} ballot identifiers, none in {rows} rows of {len(IDENTITY_TABLES)} identity-side tables")


def read_text(path: Path) -> str:
    data = path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):  # Windows PowerShell 5.1 writes redirected output as UTF-16
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def log_files(project_dir: Path, log_dir: Path) -> list[Path]:
    """SR-12: every file in the configured log folder, and every *.log file in the project."""
    files = {p for p in log_dir.rglob("*") if p.is_file()} if log_dir.is_dir() else set()
    for folder, dirs, names in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        files |= {Path(folder) / n for n in names if n.endswith(".log")}
    return sorted(files)


def check_logs(db: Session, identifiers: set[str], project_dir: Path, log_dir: Path) -> Check:
    """SR-12 (d): log files and the audit log name no ballot id, token hash or receipt."""
    name = "d. logs"
    hits: list[str] = []
    entries = 0
    for (line,) in db.execute(text("SELECT t::text FROM audit_log AS t")):
        entries += 1
        if identifiers_in(line) & identifiers:
            hits.append("audit_log")
    files = log_files(project_dir, log_dir)
    hits += [path.name for path in files if identifiers_in(read_text(path)) & identifiers]
    if hits:
        return Check(name, "FAIL", f"ballot identifiers in: {', '.join(sorted(set(hits)))}")
    return Check(name, "PASS", f"{len(files)} log file(s) and {entries} audit log entries: no ballot identifiers")


def without_ballot_data(dump: str) -> str:
    """SR-12: a plain SQL dump with the ballot tables' COPY blocks and INSERT lines taken out."""
    names = [f"{prefix}{table}" for table in BALLOT_TABLES for prefix in ("public.", "")]
    copy_starts = tuple(f"COPY {n} " for n in names)
    insert_starts = tuple(f"INSERT INTO {n} " for n in names)
    kept: list[str] = []
    in_ballot_copy = False
    for line in dump.splitlines():
        if in_ballot_copy:
            in_ballot_copy = line != "\\."
        elif line.startswith(copy_starts):
            in_ballot_copy = True
        elif not line.startswith(insert_starts):
            kept.append(line)
    return "\n".join(kept)


def identity_markers(db: Session) -> tuple[set[str], set[str]]:
    usernames = {name.lower() for name in db.scalars(text("SELECT username FROM accounts"))}
    people = {str(i).lower() for i in db.scalars(text("SELECT id FROM accounts UNION ALL SELECT id FROM electoral_roll"))}
    return usernames, people


def has_identity_marker(content: str, usernames: set[str], people: set[str]) -> bool:
    if EMAIL.search(content):
        return True
    if {m.lower() for m in UUID_PATTERN.findall(content)} & people:
        return True
    return bool({word.lower() for word in WORD.findall(content)} & usernames)


SQL_DUMP = re.compile(r"^(COPY|INSERT INTO) ", re.MULTILINE)


def check_files(db: Session, identifiers: set[str], files: list[Path]) -> Check:
    """
    SR-12 (e): backup and export files. In a plain SQL dump, no ballot identifier may appear outside
    the ballot tables' own data. Any other file (an export) may not hold a ballot identifier together
    with an identity marker.
    """
    name = "e. backups and exports"
    if not files:
        return Check(name, "SKIPPED", "no backup or export files given (use --file)")
    usernames, people = identity_markers(db)
    problems: list[str] = []
    for path in files:
        if not path.is_file():
            problems.append(f"{path.name} (not found)")
            continue
        content = read_text(path)
        if SQL_DUMP.search(content):
            outside = identifiers_in(without_ballot_data(content)) & identifiers
            if outside:
                problems.append(f"{path.name} ({len(outside)} ballot identifier(s) outside the ballot tables' data)")
        elif identifiers_in(content) & identifiers and has_identity_marker(content, usernames, people):
            problems.append(f"{path.name} (ballot identifiers together with identity data)")
    if problems:
        return Check(name, "FAIL", "; ".join(problems))
    return Check(name, "PASS", f"{len(files)} file(s): ballot identifiers only where they belong")


def run_audit(db: Session, files: list[Path], project_dir: Path, log_dir: Path) -> list[Check]:
    """SR-12: checks a to e, in order."""
    identifiers = ballot_identifiers(db)
    return [
        check_foreign_keys(db),
        check_ballot_columns(db),
        check_identity_tables(db, identifiers),
        check_logs(db, identifiers, project_dir, log_dir),
        check_files(db, identifiers, files),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-12: confirm no persistent link between electors and ballots")
    parser.add_argument("--file", type=Path, action="append", default=[], help="a backup or export file to check")
    args = parser.parse_args(argv)
    print("SR-12 separation audit")
    with SessionLocal() as db:
        checks = run_audit(db, args.file, PROJECT_DIR, settings.log_dir)
    for check in checks:
        print(f"{check.status:<8} {check.name}: {check.reason}")
    failed = sum(check.status == "FAIL" for check in checks)
    skipped = sum(check.status == "SKIPPED" for check in checks)
    print(f"Summary: {len(checks) - failed - skipped} passed, {failed} failed, {skipped} skipped")
    # SR-12 (f): the one-line verdict
    print("SR-12 separation audit: PASS" if not failed else f"SR-12 separation audit: FAIL ({failed} checks)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
