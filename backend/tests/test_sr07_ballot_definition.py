"""
SR-07: ballots come only from a signed, versioned ballot definition approved by
two distinct delegates and activated before polls open. Altered, expired,
wrongly signed and single-approver definitions are rejected.

Delegate keys and the keyring come from the delegate_keys fixture (conftest.py),
made by the delegate script itself in a temporary folder.
"""

import base64
import json
import re
from contextlib import nullcontext
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.ballot_definitions import active_definition, canonical, payload_hash, verify_definition
from app.config import BACKEND_DIR, settings
from app.main import app
from app.models import (
    AuditLogEntry,
    BallotDefinition,
    BallotToken,
    Candidate,
    Election,
    ElectionStatus,
    VoterParticipation,
)
from scripts import ballot_definition as script
from scripts.ballot_definition import activate, build_payload, sign, write_keyring

UNAVAILABLE = (503, {"detail": "ballot_unavailable"})


@pytest.fixture
def future(db_session: Session, election, clock) -> Election:
    """SR-07: a second election whose polls open in 48 hours, with the same divisions and candidates."""
    upcoming = Election(
        name="Future election",
        status=ElectionStatus.OPEN,
        starts_at=clock.now + timedelta(hours=48),
        ends_at=clock.now + timedelta(days=30),
        polling_date=(clock.now + timedelta(days=30)).date(),
    )
    db_session.add(upcoming)
    db_session.flush()
    for name, division in election.divisions.items():
        for c in election.candidates[name]:
            db_session.add(
                Candidate(
                    election_id=upcoming.id,
                    division_id=division.id,
                    given_name=c.given_name,
                    surname=c.surname,
                    party=c.party,
                    ballot_position=c.ballot_position,
                )
            )
    db_session.commit()
    return upcoming


def payload_for(db_session: Session, election: Election, clock, **changes) -> str:
    """The election's next version, valid from an hour ago until polls close, with any fields changed."""
    content = json.loads(build_payload(db_session, election, clock.now - timedelta(hours=1), election.ends_at))
    content.update(changes)
    return canonical(content)


def signed(keys: dict, payload: str, *delegates: str) -> list[dict[str, str]]:
    return [sign(keys[d], payload) for d in delegates]


def outcome(response) -> tuple[int, dict]:
    return response.status_code, response.json()


def ballot_entry(payload: str, division: str) -> dict:
    return next(d for d in json.loads(payload)["divisions"] if d["name"] == division)


def tamper(db_session: Session, election_id, old: str, new: str) -> None:
    """Changes the stored active payload directly in the database. The app itself never does this."""
    definition = active_definition(db_session, election_id)
    db_session.execute(
        update(BallotDefinition).where(BallotDefinition.id == definition.id).values(payload=definition.payload.replace(old, new))
    )
    db_session.commit()


def start_api() -> None:
    """The API's start-up, against the test database (the client fixture has pointed it there)."""
    with TestClient(app):
        pass


# ---------------------------------------------------------------
# Activation and serving
# ---------------------------------------------------------------


def test_two_delegates_activate_and_the_ballot_is_the_definition(
    client: TestClient, db_session: Session, election, future, delegate_keys, make_voter, sign_in, clock
) -> None:
    """SR-07 test 1: signed by two distinct delegates it activates, and once polls open the ballot is exactly it."""
    payload = payload_for(db_session, future, clock)

    assert activate(db_session, payload, signed(delegate_keys, payload, "delegate_a", "delegate_b")) == "ok"

    stored = active_definition(db_session, future.id)
    assert (stored.version, stored.payload) == (1, payload)
    election.election.status = ElectionStatus.CLOSED
    db_session.commit()
    clock.now = future.starts_at + timedelta(minutes=1)
    sign_in(make_voter(division="Northgate"))
    ballot = client.get("/api/ballot").json()
    entry = ballot_entry(payload, "Northgate")
    assert (ballot["election_name"], ballot["division_name"], ballot["state_name"]) == (
        "Future election",
        entry["name"],
        entry["state"],
    )
    assert ballot["candidates"] == [
        {"id": c["candidate_id"], "given_name": c["given_name"], "surname": c["surname"], "party": c["party"]}
        for c in entry["candidates"]
    ]


def test_altered_payload_is_refused_at_activation(db_session: Session, future, delegate_keys, clock) -> None:
    """SR-07 test 2a: a candidate changed after signing: activation refuses it and stores nothing."""
    payload = payload_for(db_session, future, clock)
    signatures = signed(delegate_keys, payload, "delegate_a", "delegate_b")

    assert activate(db_session, payload.replace("Ortega", "Ortiz", 1), signatures) == "bad_signature"
    assert active_definition(db_session, future.id) is None


def test_altered_stored_definition_serves_nothing(
    client: TestClient, db_session: Session, election, make_voter, sign_in
) -> None:
    """SR-07 test 2b: a candidate changed in the stored payload: 503, audited, and no ballot issued (fail closed)."""
    voter = make_voter()
    tamper(db_session, election.election.id, "Whitfield", "Whitley")
    sign_in(voter)

    assert outcome(client.get("/api/ballot")) == UNAVAILABLE
    entry = db_session.scalars(select(AuditLogEntry).where(AuditLogEntry.event_type == "BALLOT_DEFINITION_INVALID")).one()
    # SR-16: the reason is a structured field
    assert (entry.actor, entry.outcome, entry.reason) == (f"account:{voter.account_id}", "failure", "bad_signature")
    assert db_session.scalar(select(func.count()).select_from(VoterParticipation)) == 0
    assert db_session.scalar(select(func.count()).select_from(BallotToken)) == 0


@pytest.mark.parametrize("problem", ["altered", "missing"])
def test_startup_refuses_an_open_election_without_a_valid_definition(
    client: TestClient, db_session: Session, election, problem: str
) -> None:
    """SR-07 test 2c: an altered or missing active definition for an open election stops the API from starting."""
    if problem == "altered":
        tamper(db_session, election.election.id, "Mei-Lin", "Mei-Ling")
    else:
        db_session.execute(delete(BallotDefinition))
        db_session.commit()

    with pytest.raises(RuntimeError, match="no valid ballot definition"):
        start_api()

    last = db_session.scalars(select(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(1)).one()
    reason = "bad_signature" if problem == "altered" else "no_active_definition"
    # SR-16: the reason is a structured field, in the configuration category
    assert (last.event_type, last.actor, last.category, last.reason) == ("BALLOT_DEFINITION_INVALID", "unknown", "configuration", reason)


def test_definition_is_valid_only_between_its_dates(db_session: Session, future, delegate_keys, clock) -> None:
    """SR-07 test 3: valid at exactly valid_from and exactly valid_until, not a moment either side."""
    valid_from, valid_until = clock.now + timedelta(hours=1), clock.now + timedelta(hours=10)
    payload = payload_for(
        db_session, future, clock, valid_from=valid_from.isoformat(), valid_until=valid_until.isoformat()
    )
    signatures = signed(delegate_keys, payload, "delegate_a", "delegate_b")
    tick = timedelta(microseconds=1)

    for moment, expected in (
        (valid_from - tick, "not_yet_valid"),
        (valid_from, "ok"),
        (valid_until, "ok"),
        (valid_until + tick, "expired"),
    ):
        clock.now = moment
        assert verify_definition(payload, signatures, future.id, None) == expected, moment
    assert activate(db_session, payload, signatures) == "expired"


@pytest.mark.parametrize("problem", ["unknown key", "other content", "garbled", "truncated", "other election's"])
def test_incorrectly_signed_definitions_are_refused(
    db_session: Session, election, future, delegate_keys, clock, problem: str
) -> None:
    """SR-07 test 4: an unknown key, a signature over other content, a damaged one or another election's."""
    payload = payload_for(db_session, future, clock)
    good = sign(delegate_keys["delegate_b"], payload)
    real = sign(delegate_keys["delegate_a"], payload)
    first = {
        "unknown key": sign(Ed25519PrivateKey.generate(), payload),
        "other content": sign(delegate_keys["delegate_a"], payload.replace("Ortega", "Ortiz", 1)),
        "garbled": {**real, "signature": "not base64 at all!"},
        "truncated": {**real, "signature": base64.b64encode(base64.b64decode(real["signature"])[:-1]).decode()},
        "other election's": sign(delegate_keys["delegate_a"], payload_for(db_session, election.election, clock)),
    }[problem]

    assert activate(db_session, payload, [first, good]) == "bad_signature"
    assert active_definition(db_session, future.id) is None


def test_a_definition_signed_for_another_election_is_refused(db_session: Session, election, future, delegate_keys, clock) -> None:
    """SR-07 test 4b: a validly signed definition for one election cannot pass as another's."""
    payload = payload_for(db_session, future, clock)
    signatures = signed(delegate_keys, payload, "delegate_a", "delegate_b")

    assert verify_definition(payload, signatures, election.election.id, None) == "election_mismatch"


@pytest.mark.parametrize("approvals", ["one signature", "the same signature twice", "two keys of one delegate"])
def test_a_single_approver_is_not_enough(
    db_session: Session, future, delegate_keys, clock, tmp_path, monkeypatch: pytest.MonkeyPatch, approvals: str
) -> None:
    """SR-07 test 5: approvals count per distinct delegate, so one delegate can never activate alone."""
    payload = payload_for(db_session, future, clock)
    first = sign(delegate_keys["delegate_a"], payload)
    if approvals == "one signature":
        signatures = [first]
    elif approvals == "the same signature twice":
        signatures = [first, dict(first)]
    else:
        second_key = Ed25519PrivateKey.generate()
        write_keyring(tmp_path / "keyring.json", [*delegate_keys.items(), ("delegate_a", second_key)])
        monkeypatch.setattr(settings, "delegate_keyring_path", tmp_path / "keyring.json")
        signatures = [first, sign(second_key, payload)]

    assert activate(db_session, payload, signatures) == "not_enough_delegates"


def test_versions_must_follow_on_from_the_active_one(db_session: Session, future, delegate_keys, clock) -> None:
    """SR-07 test 6: only active version + 1, with the active version's hash, is accepted."""
    approve = lambda p: signed(delegate_keys, p, "delegate_a", "delegate_c")  # noqa: E731
    first = payload_for(db_session, future, clock)
    assert activate(db_session, first, approve(first)) == "ok"
    second = payload_for(db_session, future, clock)
    assert activate(db_session, second, approve(second)) == "ok"

    for version in (1, 2, 4):  # older, equal, skipped
        stale = payload_for(db_session, future, clock, version=version)
        assert activate(db_session, stale, approve(stale)) == "bad_version", version
    wrong_chain = payload_for(db_session, future, clock, prev_hash=payload_hash(first))
    assert activate(db_session, wrong_chain, approve(wrong_chain)) == "bad_prev_hash"
    assert active_definition(db_session, future.id).version == 2


def test_activation_needs_24_hours_before_polls_open(db_session: Session, future, delegate_keys, clock) -> None:
    """SR-07 test 7: exactly 24 hours before polls open is accepted; a minute later is refused."""
    clock.now = future.starts_at - timedelta(hours=24)
    first = payload_for(db_session, future, clock)
    assert activate(db_session, first, signed(delegate_keys, first, "delegate_a", "delegate_b")) == "ok"

    clock.now = future.starts_at - timedelta(hours=24) + timedelta(minutes=1)
    second = payload_for(db_session, future, clock)
    assert activate(db_session, second, signed(delegate_keys, second, "delegate_a", "delegate_b")) == "insufficient_lead"


@pytest.mark.parametrize("after", [timedelta(0), timedelta(minutes=1)])
def test_activation_after_polls_open_is_refused(db_session: Session, future, delegate_keys, clock, after) -> None:
    """SR-07 test 8: once polls are open (from the opening moment itself) nothing can be activated."""
    clock.now = future.starts_at + after
    payload = payload_for(db_session, future, clock)

    assert activate(db_session, payload, signed(delegate_keys, payload, "delegate_a", "delegate_b")) == "polls_open"
    assert active_definition(db_session, future.id) is None


def test_a_new_version_leaves_the_old_one_untouched(db_session: Session, future, delegate_keys, clock) -> None:
    """SR-07 test 9: version 2 retires version 1 without changing its payload or signatures."""
    first = payload_for(db_session, future, clock)
    first_signatures = signed(delegate_keys, first, "delegate_a", "delegate_b")
    activate(db_session, first, first_signatures)
    second = payload_for(db_session, future, clock)
    activate(db_session, second, signed(delegate_keys, second, "delegate_b", "delegate_c"))

    db_session.expire_all()
    rows = db_session.scalars(
        select(BallotDefinition).where(BallotDefinition.election_id == future.id).order_by(BallotDefinition.version)
    ).all()
    assert [(r.version, r.is_active) for r in rows] == [(1, False), (2, True)]
    assert (rows[0].payload, rows[0].signatures) == (first, first_signatures)
    assert json.loads(rows[1].payload)["prev_hash"] == payload_hash(first)


def test_candidates_outside_the_definition_are_ignored_and_refused(
    client: TestClient, db_session: Session, election, make_voter, sign_in
) -> None:
    """SR-07 test 10: a candidate added after activation is not on the ballot and cannot be ranked."""
    late = Candidate(
        election_id=election.election.id,
        division_id=election.divisions["Northgate"].id,
        given_name="Late",
        surname="Addition",
        party="Independent",
        ballot_position=4,
    )
    db_session.add(late)
    db_session.commit()
    sign_in(make_voter(division="Northgate"))

    ballot = client.get("/api/ballot").json()
    ids = [c["id"] for c in ballot["candidates"]]
    submit = lambda ranking: client.post(  # noqa: E731
        "/api/ballot/submit", json={"ballot_token": ballot["ballot_token"], "ranked_candidate_ids": ranking}
    )

    assert late.id not in ids and len(ids) == 3
    # SR-08: refused content is now 422 (it was 400)
    assert outcome(submit([*ids, late.id])) == (422, {"detail": "invalid_ballot"})
    assert submit(ids).status_code == 200


# ---------------------------------------------------------------
# The delegate script, the source and the audit log
# ---------------------------------------------------------------


def test_delegate_script_end_to_end(
    db_session: Session, future, clock, tmp_path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """SR-07 test 11: build, sign and activate through the script's main; bad input exits non-zero with a reason."""
    monkeypatch.setattr(script, "SessionLocal", lambda: nullcontext(db_session))
    definition = tmp_path / "definition.json"
    window = ["--valid-from", (clock.now - timedelta(hours=1)).isoformat(), "--valid-until", future.ends_at.isoformat()]

    script.main(["build", "--election", str(future.id), *window, "--out", str(definition)])
    for delegate in ("delegate_a", "delegate_b"):
        script.main(["sign", "--definition", str(definition), "--delegate", delegate])
    signature = lambda d: str(tmp_path / f"definition.json.{d}.sig.json")  # noqa: E731

    with pytest.raises(SystemExit, match="Rejected: not_enough_delegates"):
        script.main(["activate", "--definition", str(definition), "--signature", signature("delegate_a")])
    script.main(
        ["activate", "--definition", str(definition), "--signature", signature("delegate_a"), "--signature", signature("delegate_b")]
    )

    assert "Activated version 1" in capsys.readouterr().out
    assert active_definition(db_session, future.id).payload == definition.read_bytes().decode()
    for bad in (
        ["sign", "--definition", str(definition), "--delegate", "delegate_z"],
        ["build", "--valid-from", "2026-01-01T00:00:00", "--valid-until", "2027-01-01T00:00:00", "--out", str(definition)],
        ["activate", "--definition", str(tmp_path / "missing.json"), "--signature", signature("delegate_a")],
    ):
        with pytest.raises(SystemExit) as exit_info:
            script.main(bad)
        assert exit_info.value.code not in (0, None)


def test_app_code_never_reads_a_delegate_private_key() -> None:
    """SR-07 test 12: nothing under app/ loads a private key, signs, or imports the delegate script."""
    forbidden = re.compile(
        r"load_pem_private_key|Ed25519PrivateKey|private_bytes|from scripts|import scripts|\.sign\(|delegate_[a-z]+\.pem"
    )
    for path in (BACKEND_DIR / "app").rglob("*.py"):
        assert not forbidden.search(path.read_text(encoding="utf-8")), path


def test_audit_events_hold_no_payload_or_signature_material(
    client: TestClient, db_session: Session, election, future, delegate_keys, make_voter, sign_in, clock, audit_text
) -> None:
    """SR-07 test 13: activated, rejected and invalid events carry an actor and a reason code only.
    SR-16: plus the allow-listed outcome and role; every column is searched for definition material."""
    before = db_session.scalar(select(func.coalesce(func.max(AuditLogEntry.id), 0)))
    payload = payload_for(db_session, future, clock)
    signatures = signed(delegate_keys, payload, "delegate_a", "delegate_b")
    activate(db_session, payload, signatures[:1])
    activate(db_session, payload, signatures)
    voter = make_voter()
    tamper(db_session, election.election.id, "Ortega", "Ortiz")
    sign_in(voter)
    client.get("/api/ballot")

    rows = db_session.scalars(
        select(AuditLogEntry).where(AuditLogEntry.id > before, AuditLogEntry.event_type.like("BALLOT_DEFINITION_%"))
    ).all()
    assert [(r.event_type, r.actor, r.outcome, r.reason) for r in rows] == [
        ("BALLOT_DEFINITION_REJECTED", "script", "rejected", "not_enough_delegates"),
        ("BALLOT_DEFINITION_ACTIVATED", "script", "success", None),
        ("BALLOT_DEFINITION_INVALID", f"account:{voter.account_id}", "failure", "bad_signature"),
    ]
    recorded = audit_text(before)
    material = [payload_hash(payload), "Ortega", "Whitfield"] + [s["signature"] for s in signatures] + [s["key_id"] for s in signatures]
    assert [m for m in material if m in recorded] == []
