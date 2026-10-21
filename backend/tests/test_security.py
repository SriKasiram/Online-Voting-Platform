"""The security helpers on their own."""

import hashlib
import json

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLogEntry
from app.security import (
    RateLimiter,
    audit,
    decrypt,
    encrypt,
    enrolment_code_hash,
    hash_password,
    normalise_date,
    normalise_name,
    roll_lookup,
    verify_password,
)


def test_names_are_compared_without_case_accents_or_extra_spaces() -> None:
    assert normalise_name("  José   O'Brien ") == "jose o'brien"
    assert roll_lookup(" ZOË ", "Smith", "1990-01-01", "3000") == roll_lookup("zoe", "SMITH", "1990-01-01", " 30 00")
    assert roll_lookup("Zoe", "Smith", "1990-01-01", "3000") != roll_lookup("Zoe", "Smith", "1990-01-02", "3000")


def test_dates_must_be_real_iso_dates() -> None:
    assert normalise_date(" 1990-01-01 ") == "1990-01-01"
    assert normalise_date("01/01/1990") == ""
    assert normalise_date("1990-02-30") == ""


def test_enrolment_codes_ignore_case_spaces_and_hyphens() -> None:
    assert enrolment_code_hash("abcd-efgh") == enrolment_code_hash(" ABCD EFGH ")
    assert enrolment_code_hash("ABCD-EFGH") != enrolment_code_hash("ABCD-EFGJ")


def test_encrypted_values_only_decrypt_in_their_own_column() -> None:
    blob = encrypt("1990-01-01", "electoral_roll.date_of_birth")

    assert b"1990-01-01" not in blob
    assert decrypt(blob, "electoral_roll.date_of_birth") == "1990-01-01"
    # A random nonce every time, so equal values never look equal
    assert encrypt("1990-01-01", "electoral_roll.date_of_birth") != blob
    with pytest.raises(InvalidTag):
        decrypt(blob, "electoral_roll.postcode")


def test_passwords_use_argon2id() -> None:
    stored = hash_password("correct horse battery")

    assert stored.startswith("$argon2id$")
    assert verify_password(stored, "correct horse battery")
    assert not verify_password(stored, "wrong horse battery")
    assert not verify_password(None, "correct horse battery")
    # A value that is not an Argon2 hash, such as an old plain-text password, never matches
    assert not verify_password("correct horse battery", "correct horse battery")


def test_audit_entries_form_a_hash_chain(db_session: Session) -> None:
    audit(db_session, "TEST_EVENT", actor="unknown", step="one")
    audit(db_session, "TEST_EVENT", actor="unknown", step="two")

    first, second = db_session.scalars(select(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(2)).all()[::-1]

    assert second.prev_hash == first.hash
    body = {"created_at": second.created_at.isoformat(), "event_type": "TEST_EVENT", "actor": "unknown", "details": {"step": "two"}}
    assert second.hash == hashlib.sha256(second.prev_hash + json.dumps(body, sort_keys=True).encode()).digest()


def test_rate_limiter_blocks_after_the_limit() -> None:
    limiter = RateLimiter()

    assert [limiter.allow("key", limit=2, window_seconds=60) for _ in range(3)] == [True, True, False]
    assert limiter.allow("other key", limit=2, window_seconds=60)

    limiter.clear()
    assert limiter.allow("key", limit=2, window_seconds=60)
