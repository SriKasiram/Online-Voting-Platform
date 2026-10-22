"""
SR-08: House of Representatives preference rules, checked on the server.

A ballot arrives as an ordered list of candidate ids: the first id is number 1,
the second number 2, and so on. So repeated numbers, gaps and a missing first
preference cannot occur, because the numbers are positions in a list. Ticks,
crosses and identifying writing cannot be produced by the interface either.
What remains is whether the list numbers every candidate exactly once.

Every box must be numbered. The one-blank-box savings provision of the real
House rules is not implemented (design only), so N-1 entries are informal.
"""

from collections.abc import Collection, Sequence
from typing import Literal, NamedTuple


class Verdict(NamedTuple):
    outcome: Literal["formal", "informal", "invalid"]
    # informal: blank or incomplete_order. invalid: too_many, invalid_candidate or duplicate_candidate.
    reason: str | None = None


def evaluate_house_ballot(division_candidate_ids: Collection[int], ranked_ids: Sequence[int]) -> Verdict:
    """
    SR-08: formal, informal or invalid, applying the rules in order:
    invalid (not a candidate of this division, repeated, or more than N),
    then informal blank (nothing ranked), then formal (all N, each once, in
    preference order), and anything else is informal incomplete_order.
    """
    candidates = set(division_candidate_ids)
    # Invalid: no interface produces these, so they suggest tampering
    if len(ranked_ids) > len(candidates):
        return Verdict("invalid", "too_many")
    if any(candidate not in candidates for candidate in ranked_ids):
        return Verdict("invalid", "invalid_candidate")
    if len(set(ranked_ids)) != len(ranked_ids):
        return Verdict("invalid", "duplicate_candidate")
    if not ranked_ids:
        return Verdict("informal", "blank")
    if len(ranked_ids) == len(candidates):
        return Verdict("formal")
    return Verdict("informal", "incomplete_order")
