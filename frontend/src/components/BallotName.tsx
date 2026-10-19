import type { Candidate } from "../api/types";

/** A candidate as printed on a ballot paper: SURNAME, Given names, with the party underneath. */
export default function BallotName({ candidate }: { candidate: Candidate }) {
  return (
    <span className="cand-text">
      <span className="cand-name">
        <span className="surname">{candidate.surname}</span>, {candidate.givenName}
      </span>
      <span className="cand-party">{candidate.party}</span>
    </span>
  );
}
