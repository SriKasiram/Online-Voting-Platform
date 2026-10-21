import { useEffect, useRef, useState } from "react";
import type { BallotDefinition, Candidate } from "../api/types";
import BallotName from "../components/BallotName";
import {
  ArrowRightIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  CloseIcon,
  HelpIcon,
  UndoIcon,
} from "../components/Icons";
import { ErrorAlert } from "../components/Messages";
import {
  checkRanking,
  movePreference,
  removePreference,
  toggleCandidate,
  type Ranking,
} from "../lib/ballotRules";
import { useFocusOnMount } from "../lib/hooks";

/** Everyday form, e.g. "Hana Ortega". The ballot paper itself uses BallotName. */
function fullName(candidate: Candidate): string {
  return `${candidate.givenName} ${candidate.surname}`;
}

/** "1 box" or "3 boxes". */
function boxes(count: number): string {
  return `${count} ${count === 1 ? "box" : "boxes"}`;
}

type Props = {
  ballot: BallotDefinition;
  ranking: Ranking;
  onRankingChange: (ranking: Ranking) => void;
  onReview: () => void;
};

type Action = "up" | "down" | "remove";

const RING = 2 * Math.PI * 26;

export default function Ballot({ ballot, ranking, onRankingChange, onReview }: Props) {
  const heading = useFocusOnMount<HTMLHeadingElement>();
  const prefList = useRef<HTMLOListElement>(null);
  const firstCandidate = useRef<HTMLButtonElement>(null);

  const [history, setHistory] = useState<Ranking[]>([]);
  const [stamp, setStamp] = useState<{ id: number; count: number } | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const [showMissing, setShowMissing] = useState(false);
  const [focusTarget, setFocusTarget] = useState<{ index: number; action: Action } | null>(null);

  const ids = ballot.candidates.map((c) => c.id);
  const byId = new Map(ballot.candidates.map((c) => [c.id, c]));
  const total = ids.length;
  const numbered = ranking.length;
  const { valid, remaining } = checkRanking(ids, ranking);

  function commit(next: Ranking, message: string, stampId?: number) {
    setHistory((h) => [...h, ranking]);
    onRankingChange(next);
    setAnnouncement(message);
    setShowMissing(false);
    if (stampId !== undefined) setStamp((s) => ({ id: stampId, count: (s?.count ?? 0) + 1 }));
  }

  function handleToggle(candidate: Candidate) {
    const at = ranking.indexOf(candidate.id);
    const next = toggleCandidate(ranking, candidate.id);
    if (at === -1) {
      commit(next, `${fullName(candidate)} is number ${numbered + 1}.`, candidate.id);
    } else {
      const shifted = at < next.length ? " Later numbers moved up." : "";
      commit(next, `${fullName(candidate)} removed.${shifted}`);
    }
  }

  function handleMove(index: number, step: -1 | 1) {
    const next = movePreference(ranking, index, step);
    const moved = byId.get(next[index + step]);
    if (!moved) return;
    commit(next, `${fullName(moved)} is now number ${index + step + 1}.`, moved.id);
    setFocusTarget({ index: index + step, action: step === -1 ? "up" : "down" });
  }

  function handleRemove(index: number) {
    const removed = byId.get(ranking[index]);
    if (!removed) return;
    const next = removePreference(ranking, index);
    const shifted = index < next.length ? " Later numbers moved up." : "";
    commit(next, `${fullName(removed)} removed.${shifted}`);
    setFocusTarget({ index: Math.min(index, next.length - 1), action: "remove" });
  }

  function handleUndo() {
    if (history.length === 0) return;
    onRankingChange(history[history.length - 1]);
    setHistory((h) => h.slice(0, -1));
    setShowMissing(false);
    setAnnouncement("Last change undone.");
  }

  function handleClear() {
    if (numbered > 0) commit([], "All numbers cleared. Select Undo to bring them back.");
  }

  function handleReview() {
    if (!valid) {
      setShowMissing(true);
      return;
    }
    onReview();
  }

  // Ctrl+Z (or Cmd+Z) undoes the last change, unless the voter is typing in a field
  const undoRef = useRef(handleUndo);
  undoRef.current = handleUndo;
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== "z") return;
      if (event.target instanceof HTMLElement && event.target.closest("input, textarea")) return;
      if (document.querySelector("dialog[open]")) return;
      event.preventDefault();
      undoRef.current();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  // Keep keyboard focus on the row that just moved, so arrow presses can repeat
  useEffect(() => {
    if (!focusTarget) return;
    const row = prefList.current?.children[focusTarget.index];
    const buttons = row ? Array.from(row.querySelectorAll<HTMLButtonElement>("[data-action]")) : [];
    const target =
      buttons.find((b) => b.dataset.action === focusTarget.action && !b.disabled) ??
      buttons.find((b) => !b.disabled);
    if (target) target.focus();
    else firstCandidate.current?.focus();
    setFocusTarget(null);
  }, [focusTarget]);

  const missingMessage = `Number ${boxes(remaining)} more before you review. Every box needs a number for your vote to count.`;

  return (
    <section className="screen ballot-screen" aria-labelledby="ballot-title">
      <div className="screen-head">
        <div className="titles">
          <p className="eyebrow">{ballot.electionName}</p>
          <h1 id="ballot-title" ref={heading} tabIndex={-1}>
            Number your ballot
          </h1>
          <p className="sub">
            Division of {ballot.divisionName}, {ballot.stateName}. {total} candidates.
          </p>
        </div>
        <details className="how">
          <summary>
            <HelpIcon />
            How preferential voting works
            <span className="chev">
              <ChevronDownIcon size={16} />
            </span>
          </summary>
          <p>
            Your number 1 is your first choice. If no candidate has more than half of the
            first-choice votes, the candidate with the fewest votes is removed and their ballots go to
            each voter's next number. This repeats until one candidate has more than half.
          </p>
        </details>
      </div>

      <div className="ballot-layout">
        <div className={showMissing ? "sheet show-missing" : "sheet"}>
          <div className="sheet-head">
            <span className="sheet-kind">Ballot paper</span>
            <span className="sheet-house">{ballot.electionName}</span>
          </div>
          <div className="sheet-intro">
            <p className="sheet-division">Electoral Division of {ballot.divisionName}</p>
            <p className="sheet-instr">Number the boxes from 1 to {total} in the order of your choice.</p>
            <p className="sheet-hint">
              Select a candidate to give them your next number. Select them again to remove it.
            </p>
          </div>

          <ul className="cands">
            {ballot.candidates.map((candidate, i) => {
              const at = ranking.indexOf(candidate.id);
              const ranked = at !== -1;
              const stamped = stamp?.id === candidate.id;
              const label = ranked
                ? `${fullName(candidate)}, ${candidate.party}. Number ${at + 1}. Select to remove.`
                : `${fullName(candidate)}, ${candidate.party}. Not numbered. Select to make number ${numbered + 1}.`;
              return (
                <li key={candidate.id}>
                  <button
                    ref={i === 0 ? firstCandidate : undefined}
                    type="button"
                    className={ranked ? "cand is-ranked" : "cand"}
                    aria-label={label}
                    onClick={() => handleToggle(candidate)}
                  >
                    {/* A new key replays the "stamp" animation each time a number lands */}
                    <span
                      key={stamped ? `stamp-${stamp.count}` : "box"}
                      className={stamped ? "box stamp" : "box"}
                      aria-hidden="true"
                    >
                      {ranked ? at + 1 : ""}
                    </span>
                    <BallotName candidate={candidate} />
                    <span className="cand-action" aria-hidden="true">
                      {ranked ? "Remove" : `Give number ${numbered + 1}`}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>

          <div className="sheet-foot">
            <p>Remember, number every box to make your vote count.</p>
            <div className="btns">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleUndo}
                disabled={history.length === 0}
                title="Undo (Ctrl+Z)"
              >
                <UndoIcon size={16} />
                Undo
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleClear}
                disabled={numbered === 0}
              >
                Clear all
              </button>
            </div>
          </div>
        </div>

        <aside className="prefs" aria-labelledby="prefs-title">
          <div className="prefs-head">
            <div className="ring" aria-hidden="true">
              <svg viewBox="0 0 64 64">
                <circle className="ring-track" cx="32" cy="32" r="26" />
                <circle
                  className="ring-fill"
                  cx="32"
                  cy="32"
                  r="26"
                  strokeDasharray={RING}
                  strokeDashoffset={RING * (1 - numbered / total)}
                />
              </svg>
              <span className="ring-text">
                {numbered}/{total}
              </span>
            </div>
            <div>
              <h2 id="prefs-title">Your preferences</h2>
              <p>{remaining === 0 ? "Every box is numbered" : `${numbered} of ${total} numbered`}</p>
            </div>
          </div>

          <ol className="pref-list" ref={prefList} aria-label="Your order of preference">
            {ids.map((_, i) => {
              const candidate = byId.get(ranking[i] ?? -1);
              if (!candidate) {
                const next = i === numbered;
                return (
                  <li key={`slot-${i}`} className={next ? "pref-slot is-next" : "pref-slot"}>
                    <span className="pref-rank">{i + 1}</span>
                    <span className="pref-name">{next ? "Your next choice" : ""}</span>
                  </li>
                );
              }
              const name = fullName(candidate);
              return (
                <li key={candidate.id} className={stamp?.id === candidate.id ? "pref is-new" : "pref"}>
                  <span className="pref-rank">{i + 1}</span>
                  <span className="pref-text">
                    <span className="pref-name">{name}</span>
                    <span className="pref-party">{candidate.party}</span>
                  </span>
                  <span className="pref-tools">
                    <button
                      type="button"
                      className="icon-btn"
                      data-action="up"
                      aria-label={`Move ${name} up`}
                      disabled={i === 0}
                      onClick={() => handleMove(i, -1)}
                    >
                      <ChevronUpIcon size={16} />
                    </button>
                    <button
                      type="button"
                      className="icon-btn"
                      data-action="down"
                      aria-label={`Move ${name} down`}
                      disabled={i === numbered - 1}
                      onClick={() => handleMove(i, 1)}
                    >
                      <ChevronDownIcon size={16} />
                    </button>
                    <button
                      type="button"
                      className="icon-btn"
                      data-action="remove"
                      aria-label={`Remove ${name}`}
                      onClick={() => handleRemove(i)}
                    >
                      <CloseIcon size={16} />
                    </button>
                  </span>
                </li>
              );
            })}
          </ol>

          <div className="prefs-foot">
            <p className={remaining === 0 ? "remaining is-done" : "remaining"}>
              {remaining === 0
                ? "Your ballot is complete. Review it before you submit."
                : `${boxes(remaining)} left. Number every box to make your vote count.`}
            </p>
            {showMissing && <ErrorAlert>{missingMessage}</ErrorAlert>}
            <button type="button" className="btn btn-primary btn-block prefs-review" onClick={handleReview}>
              Review ballot
              <ArrowRightIcon />
            </button>
          </div>
        </aside>
      </div>

      <div className="actionbar">
        <div className="actionbar-row">
          <div className="actionbar-text">
            <strong>
              {numbered} of {total} numbered
            </strong>
            <span className={showMissing ? "is-error" : undefined}>
              {showMissing
                ? `Number ${boxes(remaining)} more`
                : remaining === 0
                  ? "Ready to review"
                  : `${boxes(remaining)} left`}
            </span>
          </div>
          <button type="button" className="btn btn-primary" onClick={handleReview}>
            Review ballot
          </button>
        </div>
      </div>

      <p className="sr-only" aria-live="polite">
        {announcement}
      </p>
    </section>
  );
}
