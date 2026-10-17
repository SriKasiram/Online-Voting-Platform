import type { Candidate } from "../api/types";

/** Everyday form, e.g. "Hana Ortega". The ballot paper itself uses BallotName. */
export function fullName(candidate: Candidate): string {
  return `${candidate.givenName} ${candidate.surname}`;
}

/** Up to two capital letters for the signed-in voter's badge. */
export function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => word[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

/** "1 box" or "3 boxes". */
export function boxes(count: number): string {
  return `${count} ${count === 1 ? "box" : "boxes"}`;
}
