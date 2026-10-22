"""
SR-12: exports the ballot side only, as JSON Lines. Run inside backend/:

    python -m scripts.export_ballots                     # writes exports/ballots.jsonl
    python -m scripts.export_ballots --out other.jsonl

One line per ballot: {"ballot_id", "election_id", "encrypted_payload_b64"}, in ballot id order.
It reads the ballots table and nothing else: no identity-side table, no token, no receipt. It never
decrypts (the payload stays the SR-11 ciphertext). exports/ is in .gitignore.
"""

import argparse
import base64
import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.stores import ballot_rows

EXPORT_FIELDS = ("ballot_id", "election_id", "encrypted_payload_b64")


def export_ballots(db: Session, out: Path) -> int:
    """SR-12: writes every stored ballot, ordered by its random id (never arrival order). Returns the count."""
    out.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out.open("w", encoding="utf-8", newline="\n") as file:
        for ballot_id, election_id, sealed in ballot_rows(db):
            line = dict(zip(EXPORT_FIELDS, (str(ballot_id), str(election_id), base64.b64encode(bytes(sealed)).decode())))
            file.write(json.dumps(line) + "\n")
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="SR-12: export the ballot side only, encrypted, as JSON Lines")
    parser.add_argument("--out", type=Path, default=Path("exports/ballots.jsonl"), help="output file")
    args = parser.parse_args()
    with SessionLocal() as db:
        count = export_ballots(db, args.out)
    print(f"Wrote {count} encrypted ballot(s) to {args.out}. Keep it apart from any identity-side backup.")


if __name__ == "__main__":
    main()
