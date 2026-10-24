"""
SR-11, SR-12, SR-13, SR-16: the PASS, FAIL and SKIPPED lines, the summary and the verdict that the
audit and verify scripts print, and their exit codes. One format for all of them, exactly as each
script printed it before (scripts/verify_release.py stays self-contained, SR-18, and does not use it).
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

Status = Literal["PASS", "FAIL", "SKIPPED"]


@dataclass
class Check:
    """SR-11, SR-12: one check's result, as the audits report it."""

    name: str
    status: Status
    reason: str


def status_line(status: str, name: str, reason: str | None = None) -> str:
    # SR-11, SR-12, SR-13, SR-16: "PASS     name" or "FAIL     name: reason", the status padded to 8
    return f"{status:<8} {name}" if reason is None else f"{status:<8} {name}: {reason}"


def check_line(check: Check) -> str:
    return status_line(check.status, check.name, check.reason)


def tally(checks: Sequence[Check]) -> tuple[int, int, int]:
    """SR-11, SR-12: (passed, failed, skipped)."""
    failed = sum(check.status == "FAIL" for check in checks)
    skipped = sum(check.status == "SKIPPED" for check in checks)
    return len(checks) - failed - skipped, failed, skipped


def summary_line(checks: Sequence[Check]) -> str:
    passed, failed, skipped = tally(checks)
    return f"Summary: {passed} passed, {failed} failed, {skipped} skipped"


def verdict_line(title: str, ok: bool, failed: int | None = None) -> str:
    # SR-12, SR-13, SR-16: "TITLE: PASS", "TITLE: FAIL (N checks)", or "TITLE: FAIL" when nothing could be checked
    if ok:
        return f"{title}: PASS"
    return f"{title}: FAIL" if failed is None else f"{title}: FAIL ({failed} checks)"


def exit_code(ok: bool) -> int:
    # SR-11, SR-12, SR-13, SR-16: 0 when everything passed, 1 otherwise
    return 0 if ok else 1
