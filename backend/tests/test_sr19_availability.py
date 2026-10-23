"""
SR-19: availability is measured by a health probe every 30 seconds against a 99.9% target. These
tests check the health route, the probe and its log, and the availability calculation.
"""

import io
import json
import re
import ssl
import time
import urllib.error
from datetime import UTC, datetime, timedelta
from fractions import Fraction
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app import health
from app.config import settings
from app.models import AuditLogEntry
from scripts import availability_monitor as monitor
from scripts import availability_report as report

START = datetime(2027, 5, 15, 8, 0, tzinfo=UTC)
CONTEXT = ssl.create_default_context()


# ---------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------


def test_health_is_ok_without_a_session(client: TestClient) -> None:
    """SR-19: no session needed; the database answers and the keys are loaded, so 200 {"status": "ok"}."""
    response = client.get("/api/health")

    assert (response.status_code, response.json()) == (200, {"status": "ok"})


@pytest.mark.parametrize("failure", ["database down", "database too slow", "ballot key missing", "roll key missing"])
def test_health_is_unavailable_with_no_details(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    """SR-19: a failing or slow database, or a missing required key, gives 503 and the same bare body."""
    if failure == "database down":
        monkeypatch.setattr(health, "database_answers", lambda db: False)
    elif failure == "database too slow":
        # SR-19: a real query that outlasts the 2-second statement timeout
        monkeypatch.setattr(health, "HEALTH_QUERY", "SELECT pg_sleep(3)")
    elif failure == "ballot key missing":
        monkeypatch.setattr(settings, "ballot_key_file", tmp_path / "gone.key")
    else:
        monkeypatch.setattr(settings, "roll_public_key_path", tmp_path / "gone.pem")
    started = time.monotonic()

    response = client.get("/api/health")

    assert (response.status_code, response.text) == (503, '{"status":"unavailable"}')
    assert time.monotonic() - started < 3  # the slow query was cut off at 2 seconds


def test_database_check_never_raises() -> None:
    """SR-19: a database error inside the check becomes False, so the probe always gets an answer."""

    class Broken:
        def execute(self, *_args):
            raise OperationalError("SELECT 1", {}, Exception("server closed the connection"))

        def rollback(self):
            raise OperationalError("ROLLBACK", {}, Exception("no connection"))

    assert health.database_answers(Broken()) is False  # type: ignore[arg-type]


def test_health_keeps_the_headers_and_writes_no_audit_entry(client: TestClient, db_session: Session) -> None:
    """SR-19: no-store, HSTS and a request id as on every response; probes leave the SR-16 log alone."""
    before = db_session.scalar(select(func.count()).select_from(AuditLogEntry))

    responses = [client.get("/api/health") for _ in range(5)]

    assert all(r.headers["cache-control"] == "no-store" and "max-age" in r.headers["strict-transport-security"] for r in responses)
    assert len({r.headers["x-request-id"] for r in responses}) == 5
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(AuditLogEntry)) == before


# ---------------------------------------------------------------
# The probe
# ---------------------------------------------------------------


def ticking(*times: float):
    """A monotonic clock that returns these times in turn."""
    values = iter(times)
    return lambda: next(values)


def probe_with(fetch, *clock_times: float, timeout: float = 5.0) -> dict:
    return monitor.probe("https://localhost:8443/api/health", CONTEXT, timeout, fetch, ticking(*clock_times), lambda: START)


def raises(problem: BaseException):
    def fetch(*_args):
        raise problem

    return fetch


def test_a_quick_200_is_up() -> None:
    """SR-19: HTTP 200 within the timeout is the only result that counts as up."""
    assert probe_with(lambda *a: 200, 10.0, 10.042) == {
        "time": START.isoformat(), "ok": True, "status": 200, "latency_ms": 42, "error": "none",
    }


@pytest.mark.parametrize(
    ("fetch", "clock", "expected"),
    [
        (lambda *a: 200, (0.0, 6.5), {"ok": False, "status": 200, "latency_ms": 6500, "error": "timeout"}),
        (lambda *a: 503, (0.0, 0.01), {"ok": False, "status": 503, "latency_ms": 10, "error": "http_503"}),
        (raises(TimeoutError("timed out")), (0.0,), {"ok": False, "status": None, "latency_ms": None, "error": "timeout"}),
        (raises(urllib.error.URLError(TimeoutError())), (0.0,), {"ok": False, "status": None, "latency_ms": None, "error": "timeout"}),
        (raises(urllib.error.URLError(ConnectionRefusedError())), (0.0,), {"ok": False, "status": None, "latency_ms": None, "error": "connection_error"}),
        (raises(ConnectionResetError()), (0.0,), {"ok": False, "status": None, "latency_ms": None, "error": "connection_error"}),
        (
            raises(urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed"))),
            (0.0,),
            {"ok": False, "status": None, "latency_ms": None, "error": "tls_error"},
        ),
    ],
    ids=["200 too slow", "503", "timeout", "connect timeout", "refused", "reset", "bad certificate"],
)
def test_everything_else_is_down_with_its_error_code(fetch, clock, expected) -> None:
    """SR-19: a slow 200, another status, a timeout, a connection error or a TLS error is down, with its code."""
    assert probe_with(fetch, *clock) == {"time": START.isoformat()} | expected


def test_run_logs_one_line_per_probe_on_a_steady_schedule(tmp_path: Path) -> None:
    """SR-19: one JSON line per probe with the five fields, probes due every interval on the monotonic clock."""
    now = [100.0]
    slept: list[float] = []
    statuses = iter([200, 200, 503, 200])

    def fetch(*_args):
        now[0] += 0.4  # each probe takes 0.4 s, which must not push the schedule back
        return next(statuses)

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    log = tmp_path / "monitoring" / "probes.jsonl"
    out = io.StringIO()

    done = monitor.run("https://localhost:8443/api/health", CONTEXT, 30, 5, log, 4, fetch, lambda: now[0], sleep, out)

    lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert done == 4 and [r["ok"] for r in lines] == [True, True, False, True]
    assert all(set(r) == {"time", "ok", "status", "latency_ms", "error"} for r in lines)
    assert all(datetime.fromisoformat(r["time"]).utcoffset() == timedelta(0) for r in lines)
    assert [r["error"] for r in lines] == ["none", "none", "http_503", "none"]
    assert slept == pytest.approx([29.6, 29.6, 29.6])  # due at 130, 160, 190: no drift
    assert out.getvalue().count("\n") == 4 and "DOWN" in out.getvalue()


def test_the_monitor_has_no_way_to_skip_certificate_checks(capsys) -> None:
    """SR-19: no option turns TLS verification off, and nothing in the monitor disables it."""
    source = Path(monitor.__file__).read_text(encoding="utf-8")
    with pytest.raises(SystemExit):
        monitor.main(["--help"])
    options = set(re.findall(r"--[a-z-]+", capsys.readouterr().out))

    assert options == {"--help", "--url", "--cacert", "--interval", "--timeout", "--log", "--count"}
    assert "CERT_NONE" not in source and "check_hostname = False" not in source and "_create_unverified_context" not in source
    # the context the monitor builds (ssl.create_default_context) verifies the chain and the host name
    context = ssl.create_default_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


# ---------------------------------------------------------------
# The report
# ---------------------------------------------------------------


def probes(oks: list[bool], start: datetime = START, every: int = 30) -> list[report.Probe]:
    return [report.Probe(start + timedelta(seconds=every * n), ok) for n, ok in enumerate(oks)]


def write_log(path: Path, oks: list[bool]) -> Path:
    path.write_text(
        "".join(
            json.dumps({"time": p.time.isoformat(), "ok": p.ok, "status": 200 if p.ok else 503, "latency_ms": 20, "error": "none" if p.ok else "http_503"}) + "\n"
            for p in probes(oks)
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(("failures", "percent", "code"), [(1, "99.900%", 0), (2, "99.800%", 1), (0, "100.000%", 0)])
def test_999_of_1000_passes_and_998_fails(tmp_path: Path, capsys, failures: int, percent: str, code: int) -> None:
    """SR-19: 999 of 1000 is exactly 99.900% and meets 99.9%; 998 does not; all up is 100%."""
    log = write_log(tmp_path / "probes.jsonl", [True] * (1000 - failures) + [False] * failures)

    assert report.main(["--log", str(log)]) == code

    printed = capsys.readouterr().out
    assert f"Availability:       {percent}" in printed and f"Successful probes:  {1000 - failures}" in printed
    assert ("Result:             PASS" if code == 0 else "Result:             FAIL") in printed


def test_downtime_budget_and_longest_outage() -> None:
    """SR-19: failed probes x interval, period x (1 - target), and the longest run of failures x interval."""
    oks = [True] * 400 + [False] * 3 + [True] * 300 + [False] + [True] * 296

    result = report.calculate(probes(oks), target=99.9, interval=30)

    assert (result.total, result.successful, result.passed) == (1000, 996, False)
    assert result.percent == Fraction(996, 10)
    assert result.downtime_seconds == 4 * 30
    assert result.period_end - result.period_start == timedelta(seconds=999 * 30)
    assert result.budget_seconds == pytest.approx(999 * 30 * 0.001)  # 29.97 s
    assert result.longest_outage_seconds == 3 * 30


def test_from_and_to_select_the_period(tmp_path: Path, capsys) -> None:
    """SR-19: only probes from --from to --to count, and the period (and budget) is that window."""
    oks = [False] * 10 + [True] * 100 + [False] * 10
    log = write_log(tmp_path / "probes.jsonl", oks)
    start, end = START + timedelta(seconds=300), START + timedelta(seconds=300 + 99 * 30)

    result = report.calculate(report.read_probes(log), 99.9, 30, start, end)
    code = report.main(["--log", str(log), "--from", start.isoformat(), "--to", end.isoformat()])

    assert (result.total, result.successful, result.longest_outage_seconds) == (100, 100, 0)
    assert result.budget_seconds == pytest.approx(99 * 30 * 0.001)
    assert code == 0 and "Availability:       100.000%" in capsys.readouterr().out


@pytest.mark.parametrize("problem", ["missing", "empty", "malformed"])
def test_a_log_that_cannot_be_trusted_gives_exit_code_2(tmp_path: Path, capsys, problem: str) -> None:
    """SR-19: a missing or empty log, or a malformed line (named by number, never skipped), gives exit code 2."""
    log = tmp_path / "probes.jsonl"
    if problem == "empty":
        log.write_text("", encoding="utf-8")
    elif problem == "malformed":
        write_log(log, [True] * 5)
        lines = log.read_text(encoding="utf-8").splitlines()
        lines[2] = '{"time": "yesterday", "ok": "yes"}'
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert report.main(["--log", str(log)]) == 2

    printed = capsys.readouterr().out
    assert "cannot report" in printed
    if problem == "malformed":
        assert "line 3 of" in printed
