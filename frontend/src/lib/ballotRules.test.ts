import { describe, expect, it } from "vitest";
import { checkRanking, movePreference, removePreference, toggleCandidate } from "./ballotRules";

const ids = [10, 20, 30];

describe("toggleCandidate", () => {
  it("gives an unnumbered candidate the next number", () => {
    expect(toggleCandidate([], 20)).toEqual([20]);
    expect(toggleCandidate([20], 10)).toEqual([20, 10]);
  });

  it("takes the number away from a numbered candidate and moves later numbers up", () => {
    expect(toggleCandidate([20, 10, 30], 20)).toEqual([10, 30]);
  });
});

describe("movePreference", () => {
  it("swaps a preference with the one above or below", () => {
    expect(movePreference([10, 20, 30], 1, -1)).toEqual([20, 10, 30]);
    expect(movePreference([10, 20, 30], 1, 1)).toEqual([10, 30, 20]);
  });

  it("changes nothing when the move would go past either end", () => {
    const ranking = [10, 20, 30];
    expect(movePreference(ranking, 0, -1)).toBe(ranking);
    expect(movePreference(ranking, 2, 1)).toBe(ranking);
    expect(movePreference(ranking, 5, -1)).toBe(ranking);
  });
});

describe("removePreference", () => {
  it("removes one preference and moves later numbers up", () => {
    expect(removePreference([10, 20, 30], 0)).toEqual([20, 30]);
  });
});

describe("checkRanking", () => {
  it("accepts a ranking that numbers every candidate once", () => {
    expect(checkRanking(ids, [30, 10, 20])).toEqual({ valid: true, remaining: 0 });
  });

  it("rejects a partial ranking and says how many are missing", () => {
    expect(checkRanking(ids, [10, 20])).toEqual({ valid: false, remaining: 1 });
  });

  it("rejects a ballot with nothing numbered", () => {
    expect(checkRanking(ids, [])).toEqual({ valid: false, remaining: 3 });
  });

  it("rejects a candidate listed twice", () => {
    expect(checkRanking(ids, [10, 20, 20, 30]).valid).toBe(false);
  });

  it("rejects a candidate who is not on this ballot", () => {
    expect(checkRanking(ids, [10, 20, 30, 99]).valid).toBe(false);
  });
});
