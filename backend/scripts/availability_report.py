"""
SR-19: availability over a period, from the monitor's probe log. Run inside backend/:

    python -m scripts.availability_report --log monitoring/probes.jsonl
    python -m scripts.availability_report --log monitoring/probes.jsonl --from 2027-05-01T08:00:00+10:00 --to 2027-05-15T18:00:00+10:00

How it is worked out (calculate, a pure function):
  availability     = successful probes / total probes x 100, over the probes in the period
  estimated downtime = failed probes x interval
  downtime budget  = period length x (1 - target / 100), where the period runs from --from to --to,
                     or from the first to the last probe
  longest outage   = the longest run of consecutive failed probes x interval

Prints the figures and PASS or FAIL against --target (default 99.9). Exit code 0 for PASS, 1 for
FAIL, and 2 if the log is missing, empty, has no probes in the period, or has a malformed line (the
line number is given; a bad line is never skipped, because skipping it would change the figures).
Standard library only. A relative --log path is taken from the project root, as the monitor's is.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from fractions import Fraction
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
FIELDS = {"time", "ok", "status", "latency_ms", "error"}


class LogProblem(Exception):
    """SR-19: the log cannot give a trustworthy figure."""


@dataclass(frozen=True)
class Probe:
    time: datetime
    ok: bool


@dataclass(frozen=True)
class Availability:
    total: int
    successful: int
    # SR-19: exact fractions, so 999 of 1000 is exactly 99.9 % and meets a 99.9 % target
    percent: Fraction
    target: Fraction
    passed: bool
    period_start: datetime
    period_end: datetime
    downtime_seconds: float
    budget_seconds: float
    longest_outage_seconds: float


def parse_time(value: str) -> datetime:
    """SR-19: ISO 8601; a time without a zone is taken as UTC."""
    moment = datetime.fromisoformat(value)
    return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).astimezone(UTC)


def is_whole_or_null(value: object) -> bool:
    return value is None or type(value) is int


def read_probes(path: Path) -> list[Probe]:
    """SR-19: every line of the log, or LogProblem naming the first line that is not a probe record."""
    if not path.is_file():
        raise LogProblem(f"there is no probe log at {path}")
    probes = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            record = json.loads(line)
            valid = (
                isinstance(record, dict)
                and set(record) == FIELDS
                and type(record["ok"]) is bool
                and is_whole_or_null(record["status"])
                and is_whole_or_null(record["latency_ms"])
                and isinstance(record["error"], str)
            )
            moment = parse_time(record["time"]) if valid else None
        except (ValueError, TypeError, KeyError):
            moment = None
        if moment is None:
            raise LogProblem(f"line {number} of {path} is not a probe record")
        probes.append(Probe(moment, record["ok"]))
    if not probes:
        raise LogProblem(f"the probe log {path} is empty")
    return probes


def calculate(
    probes: Sequence[Probe],
    target: float = 99.9,
    interval: float = 30.0,
    start: datetime | None = None,
    end: datetime | None = None,
) -> Availability:
    """SR-19: the figures for the probes from start to end (both included). Raises LogProblem if there are none."""
    selected = sorted(
        (p for p in probes if (start is None or p.time >= start) and (end is None or p.time <= end)),
        key=lambda p: p.time,
    )
    if not selected:
        raise LogProblem("there are no probes in the selected period")
    successful = sum(p.ok for p in selected)
    percent = Fraction(successful * 100, len(selected))
    wanted = Fraction(str(target))
    period_start, period_end = start or selected[0].time, end or selected[-1].time
    period_seconds = Fraction(str((period_end - period_start).total_seconds()))
    longest = run = 0
    for p in selected:
        run = 0 if p.ok else run + 1
        longest = max(longest, run)
    return Availability(
        total=len(selected),
        successful=successful,
        percent=percent,
        target=wanted,
        passed=percent >= wanted,
        period_start=period_start,
        period_end=period_end,
        downtime_seconds=(len(selected) - successful) * interval,
        budget_seconds=float(period_seconds * (1 - wanted / 100)),
        longest_outage_seconds=longest * interval,
    )


def duration(seconds: float) -> str:
    """SR-19: 2730 -> '45 min 30 s', for reading at a glance; under a minute, to the hundredth (0.03 s)."""
    if seconds < 60 and seconds != int(seconds):
        # SR-19: a short demo period has a budget well under a second, which must not read as 0 s
        return f"{seconds:.2f} s"
    whole = round(seconds)
    hours, rest = divmod(whole, 3600)
    minutes, secs = divmod(rest, 60)
    parts = [f"{hours} h"] * bool(hours) + [f"{minutes} min"] * bool(minutes) + [f"{secs} s"]
    return " ".join(parts) if whole else "0 s"


def report_lines(result: Availability, log_path: Path) -> list[str]:
    return [
        f"SR-19 availability report: {log_path}",
        f"Period:             {result.period_start.isoformat()} to {result.period_end.isoformat()}",
        f"Total probes:       {result.total}",
        f"Successful probes:  {result.successful}",
        f"Availability:       {float(result.percent):.3f}%",
        f"Target:             {float(result.target):.3f}%",
        f"Result:             {'PASS' if result.passed else 'FAIL'}",
        f"Estimated downtime: {duration(result.downtime_seconds)}",
        f"Downtime budget:    {duration(result.budget_seconds)}",
        f"Longest outage:     {duration(result.longest_outage_seconds)}",
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-19: availability from the probe log")
    parser.add_argument("--log", type=Path, default=Path("monitoring/probes.jsonl"), help="probe log (relative to the project root)")
    parser.add_argument("--from", dest="start", type=parse_time, help="period start, ISO 8601 (default: the first probe)")
    parser.add_argument("--to", dest="end", type=parse_time, help="period end, ISO 8601 (default: the last probe)")
    parser.add_argument("--target", type=float, default=99.9, help="target availability in percent (default 99.9)")
    parser.add_argument("--interval", type=float, default=30.0, help="seconds between probes (default 30)")
    args = parser.parse_args(argv)
    log_path = args.log if args.log.is_absolute() else PROJECT_DIR / args.log
    try:
        result = calculate(read_probes(log_path), args.target, args.interval, args.start, args.end)
    except LogProblem as problem:
        print(f"SR-19 availability report: cannot report: {problem}")
        return 2
    for line in report_lines(result, log_path):
        print(line)
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
