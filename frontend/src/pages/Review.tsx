import { useRef, useState } from "react";
import type { BallotDefinition } from "../api/types";
import BallotName from "../components/BallotName";
import { ArrowLeftIcon } from "../components/Icons";
import { ErrorAlert, Spinner } from "../components/Messages";
import { checkRanking, type Ranking } from "../lib/ballotRules";
import { useFocusOnMount } from "../lib/useFocusOnMount";

type Props = {
  ballot: BallotDefinition;
  ranking: Ranking;
  onBack: () => void;
  onSubmit: (ballotToken: string, ranking: number[]) => Promise<void>;
};

export default function Review({ ballot, ranking, onBack, onSubmit }: Props) {
  const heading = useFocusOnMount<HTMLHeadingElement>();
  const confirmBox = useRef<HTMLInputElement>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const ids = ballot.candidates.map((c) => c.id);
  const check = checkRanking(ids, ranking);
  const byId = new Map(ballot.candidates.map((c) => [c.id, c]));

  async function handleSubmit() {
    setError("");
    if (!confirmed) {
      setError("Tick the box to confirm that your ballot is final.");
      confirmBox.current?.focus();
      return;
    }
    setBusy(true);
    try {
      await onSubmit(ballot.ballotToken, ranking);
    } catch {
      setError("Your ballot could not be submitted. Try again, or ask a polling official for help.");
      setBusy(false);
    }
  }

  if (!check.valid) {
    return (
      <section className="screen" aria-labelledby="review-title">
        <div className="screen-head">
          <div className="titles">
            <p className="eyebrow">{ballot.electionName}</p>
            <h1 id="review-title" ref={heading} tabIndex={-1}>
              Your ballot needs changes
            </h1>
            <p className="sub">Every box needs a number before you can submit. Go back and number the rest.</p>
          </div>
        </div>
        <button type="button" className="btn btn-primary" onClick={onBack}>
          <ArrowLeftIcon />
          Change ballot
        </button>
      </section>
    );
  }

  return (
    <section className="screen" aria-labelledby="review-title">
      <div className="screen-head">
        <div className="titles">
          <p className="eyebrow">{ballot.electionName}</p>
          <h1 id="review-title" ref={heading} tabIndex={-1}>
            Check your ballot
          </h1>
          <p className="sub">This is your order of preference. After you submit, you can't change it.</p>
        </div>
      </div>

      <div className="review-layout">
        <div className="sheet">
          <div className="sheet-head">
            <span className="sheet-kind">Your numbered ballot</span>
            <button type="button" className="btn btn-ghost btn-sm" onClick={onBack} disabled={busy}>
              Change
            </button>
          </div>
          <ol className="review-list">
            {ranking.map((id, i) => {
              const candidate = byId.get(id);
              if (!candidate) return null;
              return (
                <li key={id} className="rv">
                  <span className="box" aria-hidden="true">
                    {i + 1}
                  </span>
                  <span>
                    <span className="sr-only">Number {i + 1}: </span>
                    <BallotName candidate={candidate} />
                  </span>
                </li>
              );
            })}
          </ol>
        </div>

        <div className="card">
          <h2>Submit your ballot</h2>
          <dl className="facts">
            <dt>Ballot</dt>
            <dd>{ballot.electionName}</dd>
            <dt>Division</dt>
            <dd>{ballot.divisionName}</dd>
            <dt>Boxes numbered</dt>
            <dd>
              {ranking.length} of {ids.length}
            </dd>
          </dl>

          <label className="check" htmlFor="confirm-final">
            <input
              ref={confirmBox}
              id="confirm-final"
              type="checkbox"
              checked={confirmed}
              disabled={busy}
              onChange={(e) => {
                setConfirmed(e.target.checked);
                if (e.target.checked) setError("");
              }}
            />
            <span>I have checked my numbers. I understand I can't change my ballot after I submit it.</span>
          </label>

          {error && <ErrorAlert>{error}</ErrorAlert>}

          <button
            type="button"
            className="btn btn-primary btn-block"
            onClick={handleSubmit}
            disabled={busy}
            aria-busy={busy}
          >
            {busy ? (
              <>
                <Spinner />
                Submitting ballot
              </>
            ) : (
              "Submit ballot"
            )}
          </button>
          <button type="button" className="btn btn-secondary btn-block" onClick={onBack} disabled={busy}>
            <ArrowLeftIcon />
            Change ballot
          </button>
          <p className="fineprint">
            You will get a receipt code. It confirms that your ballot was accepted and does not show how
            you voted.
          </p>
        </div>
      </div>
    </section>
  );
}
