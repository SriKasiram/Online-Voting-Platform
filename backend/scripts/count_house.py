"""
SR-17: the House of Representatives count. Run inside backend/, only after polls close and the final
seal (python -m scripts.seal_ballots --election <id> --final):

    python -m scripts.count_house --election <election id>
    python -m scripts.count_house --election <election id> --out exports/result.json

Every check in app/house_count.py must pass, or the count stops: it prints the reason code, writes
no result file and exits with code 1. There is no option to skip a check or a ballot. On success it
prints each division's rounds, exclusions and elected candidate, and writes the result (totals only,
never a ballot) as JSON to --out, by default exports/house_result_<election id>.json; exports/ is
never committed. Uses the SR-11 ballot key and the SR-13 checkpoint public key; no private key.
"""

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from app.ballot_chain import checkpoint_file, load_checkpoint_public_key
from app.ballot_crypto import BallotKeyError, load_key
from app.config import settings
from app.db import engine
from app.house_count import CountRefused, run_count


def summary(result: dict[str, Any]) -> list[str]:
    """SR-17: the readable form of the result: rounds, exclusions and the elected candidate per division."""
    lines = [
        f"Election: {result['election']} ({result['election_id']})",
        f"Ballots counted: {result['ballots_counted']}. Final checkpoint head hash: {result['final_checkpoint']['head_hash']}",
    ]
    for division in result["divisions"]:
        lines.append("")
        if division["status"] == "no_ballots":
            lines.append(f"{division['division']}: no ballots, so no candidate is elected")
            continue
        lines.append(f"{division['division']}: {division['formal_total']} formal ballot(s)")
        for round_ in division["rounds"]:
            totals = ", ".join(f"{entry['name']} {entry['votes']}" for entry in round_["totals"])
            excluded = f"; excluded {round_['excluded']['name']}" if round_["excluded"] else ""
            lines.append(f"  Round {round_['round']}: {totals}{excluded}")
        elected = division["elected"]
        lines.append(f"  Elected: {elected['name']} ({elected['party']})")
    return lines


def write_result(path: Path, result: dict[str, Any]) -> None:
    # SR-17: written whole or not at all, so a half-written file can never pass for a result
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".partial")
    partial.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    partial.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-17: count an election's House of Representatives ballots")
    parser.add_argument("--election", type=uuid.UUID, required=True, help="the election id")
    parser.add_argument("--out", type=Path, help="the result file (default: exports/house_result_<election id>.json)")
    args = parser.parse_args(argv)
    print("SR-17 House count")
    # SR-17: the same keys the SR-11 audit and the SR-13 verify script read, and nothing more
    try:
        load_key(settings.ballot_key_file)
    except BallotKeyError as problem:
        print(f"REFUSED: the ballot key cannot be used ({problem}); nothing was counted")
        return 1
    public_path = settings.backend_path(settings.checkpoint_public_key)
    if not public_path.is_file():
        print(f"REFUSED: checkpoint public key not found ({public_path.name}); nothing was counted")
        return 1
    out = args.out or Path("exports") / f"house_result_{args.election}.json"
    try:
        result = run_count(engine, args.election, load_checkpoint_public_key(public_path), checkpoint_file(args.election))
    except CountRefused as refused:
        print(f"REFUSED: {refused.code}" + (f" ({', '.join(refused.details)})" if refused.details else ""))
        print("No result was written. Investigate the cause: no check can be skipped.")
        return 1
    for line in summary(result):
        print(line)
    write_result(out, result)
    print(f"\nResult written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
