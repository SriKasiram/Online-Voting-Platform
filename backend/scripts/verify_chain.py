"""
SR-13: verifies an election's ballot hash chain and its signed checkpoints. Run inside backend/:

    python -m scripts.verify_chain --election <election id>

Prints one PASS or FAIL line per check group, the entry count and the head hash (to record with the
release), and exits with code 1 on any failure. Uses only the checkpoint public key, and never
decrypts a ballot: the chain covers the stored ciphertext. There is no option to skip a check.
"""

import argparse
import sys
import uuid

from sqlalchemy import text

from app.ballot_chain import CHECK_GROUPS, checkpoint_file, load_checkpoint_public_key, verify_chain
from app.config import settings
from app.db import SessionLocal
# SR-16: the same failure entries as the seal script, one per reason code
from scripts.seal_ballots import record_failure


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-13: verify an election's ballot hash chain")
    parser.add_argument("--election", type=uuid.UUID, required=True, help="the election id")
    args = parser.parse_args(argv)
    public_path = settings.backend_path(settings.checkpoint_public_key)
    print("SR-13 ballot chain verification")
    if not public_path.is_file():
        print(f"FAIL     checkpoint public key not found ({public_path.name}); nothing can be verified")
        print("SR-13 chain verification: FAIL")
        return 1
    with SessionLocal() as db:
        reasons = verify_chain(db, args.election, load_checkpoint_public_key(public_path), checkpoint_file(args.election))
        entries, head = db.execute(
            text(
                "SELECT count(*), (SELECT entry_hash FROM ballot_chain WHERE election_id = :e ORDER BY position DESC LIMIT 1) "
                "FROM ballot_chain WHERE election_id = :e"
            ),
            {"e": args.election},
        ).one()
        if reasons:
            # SR-13: tampering is a security event: the reason codes are audited, nothing else
            record_failure(db, reasons)
    failed = 0
    for group, codes in CHECK_GROUPS.items():
        found = [code for code in reasons if code in codes]
        failed += bool(found)
        print(f"FAIL     {group}: {', '.join(found)}" if found else f"PASS     {group}")
    print(f"Entries: {entries}. Head hash: {head or 'none (nothing sealed yet)'}")  # SR-13: on purpose, for the release record
    print("SR-13 chain verification: PASS" if not reasons else f"SR-13 chain verification: FAIL ({failed} checks)")
    return 1 if reasons else 0


if __name__ == "__main__":
    sys.exit(main())
