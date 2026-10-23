"""
SR-17: the House of Representatives count.

Part A, load_validated_ballots: the ballots that may be counted, and nothing else. The checks run
in this order, and the first that fails stops the whole count with a reason code (CountRefused).
No ballot is ever skipped: a ballot that fails a check stops the count, so a result is either over
every sealed ballot or is not produced at all.

  a. polls_open           the clock is before the election's close (Election.ends_at)
  b. definition_invalid   the active ballot definition does not verify (SR-07), as at the close
  c. no_final_checkpoint  no valid, signed, final checkpoint for the election (SR-13)
  d. chain_invalid        verify_chain reports any problem (SR-13; its codes are kept as details)
  e.                      ballots are read only through the chain: positions 1 to the final count
  f. total_mismatch       ballots read differ from the final count, or from the electors who voted
  g. decrypt_failed       a ballot does not decrypt with its own ballot id and election (SR-11)
  h. wrong_division       its division is not a division of the active definition
  i. informal_or_invalid  it is not formal for that division's candidates (SR-08)

Part B, count_division: a full preferential count, a pure function of the candidate ids and the
rankings.

run_count does both inside one READ ONLY, REPEATABLE READ transaction, so the count sees a single
snapshot and cannot write anything. Its audit entries (SR-16) go in short transactions of their own.
Decrypted ballots exist only in memory here: never in a log, the database, the audit log or the
result, which holds totals only.
"""

import json
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import Engine, Row, func, select, text
from sqlalchemy.orm import Session

from app.audit_events import FAILURE, SCRIPT, SUCCESS
from app.ballot_chain import read_checkpoints, verify_chain
from app.ballot_crypto import DIVISION_FIELD, RANKING_FIELD, BallotDecryptionError, decrypt_ballot
from app.ballot_definitions import OK, active_definition, check_stored
from app.ballot_rules import evaluate_house_ballot
from app.models import Election, ParticipationState, VoterParticipation
from app.security import audit, utc_now


class CountRefused(Exception):
    """
    SR-17: the count stopped and produced no result. `code` is an SR-16 reason code; `details` holds
    the SR-13 codes behind chain_invalid; `checked` is how many ballots had passed every check.
    The message never holds a ballot id or any ballot content.
    """

    def __init__(self, code: str, details: Sequence[str] = (), checked: int = 0) -> None:
        super().__init__(code + (f" ({', '.join(details)})" if details else ""))
        self.code = code
        self.details = list(details)
        self.checked = checked


@dataclass(frozen=True)
class Candidate:
    candidate_id: int
    name: str
    party: str


@dataclass(frozen=True)
class DivisionPaper:
    """SR-17: one division's ballot paper, from the verified definition only."""

    division_id: int
    name: str
    candidates: tuple[Candidate, ...]


@dataclass
class CountInput:
    """SR-17: everything the calculation needs. `rankings` is decrypted content: memory only."""

    election_id: uuid.UUID
    election_name: str
    papers: dict[int, DivisionPaper]
    rankings: dict[int, list[list[int]]]
    entry_count: int
    head_hash: str


# ---------------------------------------------------------------
# A. The ballots that may be counted
# ---------------------------------------------------------------


def division_papers(payload: str) -> dict[int, DivisionPaper]:
    """SR-17: division id -> ballot paper, from the active definition's verified payload."""
    papers = {}
    for division in json.loads(payload)["divisions"]:
        candidates = tuple(
            Candidate(c["candidate_id"], f"{c['given_name']} {c['surname']}", c["party"]) for c in division["candidates"]
        )
        papers[division["division_id"]] = DivisionPaper(division["division_id"], division["name"], candidates)
    return papers


def final_checkpoint(path: Path, public_key: Ed25519PublicKey, election_id: uuid.UUID) -> dict[str, Any] | None:
    """SR-17: the election's final checkpoint, if one is there and its signature holds."""
    if not path.is_file():
        return None
    valid, _ = read_checkpoints(path, public_key)
    finals = [c for c in valid if c["final"] and c["election_id"] == str(election_id)]
    return finals[-1] if finals else None


def read_chained_ballots(session: Session, election_id: uuid.UUID, entry_count: int) -> list[Row[Any]]:
    """
    SR-17: the only way the count reads ballots: through the chain, positions 1 to entry_count, in
    chain order. A ballot that is not in the chain is never read, and nothing on the identity side
    is joined in.
    """
    return list(
        session.execute(
            text(
                "SELECT c.position, c.ballot_id, b.encrypted_payload FROM ballot_chain c "
                "JOIN ballots b ON b.id = c.ballot_id AND b.election_id = c.election_id "
                "WHERE c.election_id = :election AND c.position BETWEEN 1 AND :last ORDER BY c.position"
            ),
            {"election": election_id, "last": entry_count},
        )
    )


def check_ballot(
    blob: bytes, ballot_id: uuid.UUID, election_id: uuid.UUID, papers: dict[int, DivisionPaper], checked: int = 0
) -> tuple[int, list[int]]:
    """
    SR-17: checks g, h and i for one ballot, returning its division and ranking. Raises CountRefused
    on the first failure, with nothing of the ballot in it (the decryption error is not chained).
    """
    try:
        payload = decrypt_ballot(blob, ballot_id, election_id)
    except (BallotDecryptionError, ValueError):
        raise CountRefused("decrypt_failed", checked=checked) from None
    division_id = payload.get(DIVISION_FIELD) if isinstance(payload, dict) else None
    paper = papers.get(division_id) if type(division_id) is int else None
    if paper is None:
        raise CountRefused("wrong_division", checked=checked)
    ranking = payload.get(RANKING_FIELD)
    if (
        not isinstance(ranking, list)
        or not all(type(candidate) is int for candidate in ranking)
        or evaluate_house_ballot([c.candidate_id for c in paper.candidates], ranking).outcome != "formal"
    ):
        raise CountRefused("informal_or_invalid", checked=checked)
    return division_id, ranking


def load_validated_ballots(
    session: Session, election_id: uuid.UUID, public_key: Ed25519PublicKey, checkpoint_path: Path
) -> CountInput:
    """SR-17: checks a to i, in order; the first failure raises CountRefused and nothing is counted."""
    election = session.get(Election, election_id)
    if election is None:
        raise CountRefused("unknown_election")
    # a. counting while ballots can still arrive would count a partial election
    if utc_now() < election.ends_at:
        raise CountRefused("polls_open")
    # b. the paper every ballot is checked against must itself be the signed one, as it stood at the close
    definition = active_definition(session, election.id)
    if definition is None or check_stored(session, definition, at=election.ends_at) != OK:
        raise CountRefused("definition_invalid")
    papers = division_papers(definition.payload)
    # c. only a final seal says no more ballots belong to this election
    final = final_checkpoint(checkpoint_path, public_key, election.id)
    if final is None:
        raise CountRefused("no_final_checkpoint")
    # d. hashes, links, positions, every checkpoint, and nothing unsealed after the final seal
    problems = verify_chain(session, election.id, public_key, checkpoint_path)
    if problems:
        raise CountRefused("chain_invalid", problems)
    # e. through the chain only, up to what the final checkpoint signed
    rows = read_chained_ballots(session, election.id, final["entry_count"])
    # f. totals only: participation is identity-side and is never joined to a ballot
    voted = session.scalar(
        select(func.count())
        .select_from(VoterParticipation)
        .where(VoterParticipation.election_id == election.id, VoterParticipation.state == ParticipationState.VOTED)
    )
    if len(rows) != final["entry_count"] or len(rows) != voted:
        raise CountRefused("total_mismatch")
    # g, h, i. every ballot, none skipped
    rankings: dict[int, list[list[int]]] = {division_id: [] for division_id in papers}
    for checked, row in enumerate(rows):
        division_id, ranking = check_ballot(row.encrypted_payload, row.ballot_id, election.id, papers, checked)
        rankings[division_id].append(ranking)
    return CountInput(election.id, election.name, papers, rankings, final["entry_count"], final["head_hash"])


# ---------------------------------------------------------------
# B. The calculation
# ---------------------------------------------------------------


@dataclass(frozen=True)
class Round:
    totals: dict[int, int]
    excluded: int | None


@dataclass(frozen=True)
class DivisionCount:
    status: str  # "elected" or "no_ballots"
    formal_total: int
    rounds: tuple[Round, ...]
    elected: int | None


def break_tie(tied: list[int], rounds: Sequence[Round]) -> int:
    """
    SR-17: of candidates tied on the fewest votes, the one with fewer votes at the most recent earlier
    round in which their totals differed. If several still share the fewest there, the look-back goes
    on among them through earlier rounds. If no round separates them, the count stops for a decision.
    """
    still_tied = list(tied)
    for past in reversed(rounds):
        totals = {candidate: past.totals[candidate] for candidate in still_tied}
        if len(set(totals.values())) > 1:
            fewest = min(totals.values())
            still_tied = [candidate for candidate in still_tied if totals[candidate] == fewest]
            if len(still_tied) == 1:
                return still_tied[0]
    raise CountRefused("unresolved_tie")


def count_division(candidate_ids: Sequence[int], rankings: Sequence[Sequence[int]]) -> DivisionCount:
    """
    SR-17: a full preferential count. In each round every ballot counts for its highest-ranked
    continuing candidate. More than half of the formal ballots elects; otherwise the candidate with
    the fewest votes is excluded (ties: break_tie) and the next round starts. No database, no side
    effects, so the same input always gives the same result.
    """
    formal_total = len(rankings)
    if not formal_total:
        return DivisionCount("no_ballots", 0, (), None)
    continuing = list(candidate_ids)
    rounds: list[Round] = []
    while True:
        in_count = set(continuing)
        totals = dict.fromkeys(continuing, 0)
        for ranking in rankings:
            top = next((candidate for candidate in ranking if candidate in in_count), None)
            if top is not None:
                totals[top] += 1
        # SR-17: every counted ballot is fully ranked (SR-08), so none can exhaust; one that did was
        # not formal, and the count stops rather than carry on with fewer ballots
        if sum(totals.values()) != formal_total:
            raise CountRefused("informal_or_invalid")
        leader = max(continuing, key=lambda candidate: totals[candidate])
        if 2 * totals[leader] > formal_total:
            rounds.append(Round(totals, None))
            return DivisionCount("elected", formal_total, tuple(rounds), leader)
        fewest = min(totals.values())
        tied = [candidate for candidate in continuing if totals[candidate] == fewest]
        excluded = tied[0] if len(tied) == 1 else break_tie(tied, rounds)
        rounds.append(Round(totals, excluded))
        continuing.remove(excluded)


# ---------------------------------------------------------------
# The whole count
# ---------------------------------------------------------------


def _named(paper: DivisionPaper, candidate_id: int | None) -> dict[str, Any] | None:
    if candidate_id is None:
        return None
    candidate = next(c for c in paper.candidates if c.candidate_id == candidate_id)
    return {"candidate_id": candidate.candidate_id, "name": candidate.name, "party": candidate.party}


def calculate(counted: CountInput) -> dict[str, Any]:
    """SR-17: the result for every division of the definition: totals and names only, no ballot."""
    divisions = []
    for division_id in sorted(counted.papers):
        paper = counted.papers[division_id]
        try:
            result = count_division([c.candidate_id for c in paper.candidates], counted.rankings[division_id])
        except CountRefused as refused:
            refused.checked = counted.entry_count
            raise
        divisions.append(
            {
                "division_id": division_id,
                "division": paper.name,
                "status": result.status,
                "formal_total": result.formal_total,
                "rounds": [
                    {
                        "round": number,
                        "totals": [
                            {"candidate_id": c, "name": _named(paper, c)["name"], "votes": votes}  # type: ignore[index]
                            for c, votes in round_.totals.items()
                        ],
                        "excluded": _named(paper, round_.excluded),
                    }
                    for number, round_ in enumerate(result.rounds, start=1)
                ],
                "elected": _named(paper, result.elected),
            }
        )
    return {
        "election_id": str(counted.election_id),
        "election": counted.election_name,
        "ballots_counted": counted.entry_count,
        # SR-17: which sealed chain the result is over, for the release record (SR-13)
        "final_checkpoint": {"entry_count": counted.entry_count, "head_hash": counted.head_hash},
        "divisions": divisions,
    }


@contextmanager
def read_only_snapshot(engine: Engine) -> Iterator[Session]:
    """
    SR-17: one transaction that sees a single snapshot (REPEATABLE READ), so ballots sealed or
    marked voted while the count runs cannot make its totals disagree, and that cannot write
    (READ ONLY): the database refuses any INSERT, UPDATE or DELETE inside it. It is rolled back at
    the end; there is nothing to commit.
    """
    with engine.connect() as connection:
        connection = connection.execution_options(isolation_level="REPEATABLE READ")
        with Session(bind=connection) as session:
            # SR-17: the first statement of the transaction, before anything is read
            session.execute(text("SET TRANSACTION READ ONLY"))
            try:
                yield session
            finally:
                session.rollback()


def run_count(engine: Engine, election_id: uuid.UUID, public_key: Ed25519PublicKey, checkpoint_path: Path) -> dict[str, Any]:
    """
    SR-17: the House count for one election. Audits COUNT_STARTED, then COUNT_COMPLETED with the
    number of ballots counted, or COUNT_REFUSED with the reason code (and re-raises CountRefused).
    The audit entries are written outside the read-only transaction, each in its own short one.
    """
    with Session(engine) as db:
        audit(db, "COUNT_STARTED", outcome=SUCCESS, actor=SCRIPT, role=SCRIPT)
        db.commit()
    try:
        with read_only_snapshot(engine) as session:
            result = calculate(load_validated_ballots(session, election_id, public_key, checkpoint_path))
    except CountRefused as refused:
        with Session(engine) as db:
            audit(db, "COUNT_REFUSED", outcome=FAILURE, actor=SCRIPT, role=SCRIPT, reason=refused.code, count=refused.checked)
            db.commit()
        raise
    with Session(engine) as db:
        audit(db, "COUNT_COMPLETED", outcome=SUCCESS, actor=SCRIPT, role=SCRIPT, count=result["ballots_counted"])
        db.commit()
    return result
