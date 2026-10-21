/**
 * Client-side ballot helpers. These only give the voter quick feedback.
 * The server repeats every check and is the only one that counts.
 */

/** Candidate ids from first preference to last. */
export type Ranking = number[];

type RankingCheck = {
  /** True when every candidate has exactly one number and nothing else is listed. */
  valid: boolean;
  /** Candidates that do not have a number yet. */
  remaining: number;
};

/** Gives a candidate the next number, or takes their number away. Later numbers move up. */
export function toggleCandidate(ranking: Ranking, id: number): Ranking {
  return ranking.includes(id) ? ranking.filter((x) => x !== id) : [...ranking, id];
}

/** Swaps the preference at `index` with the one above (-1) or below (1). */
export function movePreference(ranking: Ranking, index: number, step: -1 | 1): Ranking {
  const target = index + step;
  if (index < 0 || index >= ranking.length || target < 0 || target >= ranking.length) {
    return ranking;
  }
  const next = [...ranking];
  [next[index], next[target]] = [next[target], next[index]];
  return next;
}

/** Removes one preference. Later numbers move up. */
export function removePreference(ranking: Ranking, index: number): Ranking {
  return ranking.filter((_, i) => i !== index);
}

export function checkRanking(candidateIds: number[], ranking: Ranking): RankingCheck {
  const known = new Set(candidateIds);
  const seen = new Set<number>();
  let clean = true;

  for (const id of ranking) {
    if (!known.has(id) || seen.has(id)) {
      clean = false;
      continue;
    }
    seen.add(id);
  }

  const remaining = candidateIds.filter((id) => !seen.has(id)).length;
  return { valid: clean && remaining === 0, remaining };
}
