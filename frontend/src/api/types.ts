export type Candidate = {
  id: number;
  givenName: string;
  /** Printed first and in capitals on the ballot paper, e.g. ORTEGA, Hana. */
  surname: string;
  party: string;
};

export type BallotDefinition = {
  /** One-time token issued after the eligibility check. Held in memory only. */
  ballotToken: string;
  electionName: string;
  divisionName: string;
  stateName: string;
  candidates: Candidate[];
};
