import type { BallotDefinition, Candidate } from "./types";

// All names and parties are invented for the demo.
export const MOCK_CANDIDATES: Candidate[] = [
  { id: 1, givenName: "Hana", surname: "Ortega", party: "Harbour Party" },
  { id: 2, givenName: "Daniel", surname: "Whitfield", party: "Rural Alliance" },
  { id: 3, givenName: "Mei-Lin", surname: "Tran", party: "Green Horizon" },
  { id: 4, givenName: "Samuel", surname: "Okafor", party: "Independent" },
  { id: 5, givenName: "Isabel", surname: "Carvalho", party: "Workers Voice" },
  { id: 6, givenName: "Tom", surname: "Kowalski", party: "Civic Reform" },
];

export function randomCode(length: number): string {
  // No 0, O, 1, I or L so a receipt code is easy to read aloud
  const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

export function newMockBallot(): BallotDefinition {
  return {
    ballotToken: randomCode(32),
    electionName: "House of Representatives",
    divisionName: "Melbourne",
    stateName: "Victoria",
    candidates: MOCK_CANDIDATES,
  };
}
