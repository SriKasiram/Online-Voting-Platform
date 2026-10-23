"""
SR-19: probes GET /api/health every 30 seconds and logs each result, so availability over the voting
period can be measured (python -m scripts.availability_report). Run inside backend/:

    python -m scripts.availability_monitor --url https://localhost:8443/api/health --cacert certs/dev-cert.pem
    python -m scripts.availability_monitor --url https://localhost:8443/api/health --cacert certs/dev-cert.pem --interval 5 --count 20

Standard library only (urllib and ssl), so it runs wherever Python does. The TLS certificate is
always checked: against --cacert, or the system's trusted certificates without it. There is no
option to turn that off, because a monitor that accepts any certificate could be measuring an
impostor. Relative --cacert and --log paths are taken from the project root, as SR-10's are.

A probe counts as up only if it gets HTTP 200 within --timeout seconds. Each one appends a JSON
line to --log (default monitoring/probes.jsonl, never committed): time (UTC), ok, status,
latency_ms, and error (none, timeout, connection_error, tls_error or http_<code>). It runs until
Ctrl+C, or for --count probes.
"""

import argparse
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

PROJECT_DIR = Path(__file__).resolve().parents[2]

# SR-19: fetch(url, context, timeout) -> HTTP status; raises on a timeout, a TLS or a connection error
Fetch = Callable[[str, ssl.SSLContext, float], int]


def fetch_status(url: str, context: ssl.SSLContext, timeout: float) -> int:
    """SR-19: one GET. An HTTP error status (503 and so on) is returned, not raised."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout, context=context) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def classify(problem: BaseException) -> str:
    """SR-19: the error code for a failed request, never its message (which could be long or change)."""
    reason = problem.reason if isinstance(problem, urllib.error.URLError) else problem
    if isinstance(reason, ssl.SSLError | ssl.CertificateError):
        return "tls_error"
    if isinstance(reason, TimeoutError | socket.timeout):
        return "timeout"
    return "connection_error"


def probe(
    url: str,
    context: ssl.SSLContext,
    timeout: float,
    fetch: Fetch = fetch_status,
    clock: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    """SR-19: one probe, as the line the log gets. Up only for HTTP 200 within the timeout."""
    at = now()
    started = clock()
    try:
        status: int | None = fetch(url, context, timeout)
    except (urllib.error.URLError, OSError, ssl.SSLError, ssl.CertificateError) as problem:
        return {"time": at.isoformat(), "ok": False, "status": None, "latency_ms": None, "error": classify(problem)}
    latency_ms = round((clock() - started) * 1000)
    if status != 200:
        error = f"http_{status}"
    elif latency_ms > timeout * 1000:
        # SR-19: a 200 that came too late was not available to an elector waiting on it
        error = "timeout"
    else:
        error = "none"
    return {"time": at.isoformat(), "ok": error == "none", "status": status, "latency_ms": latency_ms, "error": error}


def run(
    url: str,
    context: ssl.SSLContext,
    interval: float,
    timeout: float,
    log_path: Path,
    count: int | None = None,
    fetch: Fetch = fetch_status,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    out: TextIO = sys.stdout,
) -> int:
    """
    SR-19: probes every `interval` seconds until `count` probes (or Ctrl+C). Each probe is due at
    start + n x interval on the monotonic clock, so slow probes or a busy machine never make the
    schedule drift, and a clock change on the machine cannot skip or double a probe.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = clock()
    done = 0
    with log_path.open("a", encoding="utf-8", newline="\n") as log:
        try:
            while count is None or done < count:
                delay = start + done * interval - clock()
                if delay > 0:
                    sleep(delay)
                record = probe(url, context, timeout, fetch, clock)
                # SR-19: written and flushed at once, so stopping the monitor never loses a probe
                log.write(json.dumps(record, sort_keys=True) + "\n")
                log.flush()
                done += 1
                latency = f"{record['latency_ms']} ms" if record["latency_ms"] is not None else "-"
                print(f"{record['time']}  {'UP  ' if record['ok'] else 'DOWN'}  {record['error']:<16} {latency}", file=out)
        except KeyboardInterrupt:
            print("Stopped.", file=out)
    return done


def from_project(path: Path) -> Path:
    return path if path.is_absolute() else PROJECT_DIR / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SR-19: probe the health route and log availability")
    parser.add_argument("--url", required=True, help="the health route, for example https://localhost:8443/api/health")
    parser.add_argument("--cacert", type=Path, help="CA certificate to trust (relative to the project root); system CAs if omitted")
    parser.add_argument("--interval", type=float, default=30.0, help="seconds between probes (default 30)")
    parser.add_argument("--timeout", type=float, default=5.0, help="seconds a probe may take (default 5)")
    parser.add_argument("--log", type=Path, default=Path("monitoring/probes.jsonl"), help="probe log (relative to the project root)")
    parser.add_argument("--count", type=int, help="stop after this many probes (default: run until Ctrl+C)")
    args = parser.parse_args(argv)
    if args.interval <= 0 or args.timeout <= 0 or (args.count is not None and args.count < 1):
        parser.error("--interval, --timeout and --count must be positive")
    # SR-19: verification on, hostname checked; ssl.create_default_context never disables either
    context = ssl.create_default_context(cafile=str(from_project(args.cacert)) if args.cacert else None)
    log_path = from_project(args.log)
    print(f"SR-19 availability monitor: {args.url} every {args.interval:g} s, logging to {log_path}")
    done = run(args.url, context, args.interval, args.timeout, log_path, args.count)
    print(f"{done} probe(s) logged. Run python -m scripts.availability_report --log {args.log} for the figures.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
