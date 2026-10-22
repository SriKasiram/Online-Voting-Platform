import { useEffect, useRef } from "react";
import { formatClock } from "../lib/hooks";
import { ClockIcon } from "./Icons";

type Props = {
  open: boolean;
  secondsLeft: number;
  minutes: number;
  // SR-04: false once the server has refused another extension
  canExtend: boolean;
  onKeep: () => void;
  onSignOut: () => void;
};

/** Asks the voter, one minute before the session ends, whether they need more time. */
export default function SessionWarning({ open, secondsLeft, minutes, canExtend, onKeep, onSignOut }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);
  const keep = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const el = dialog.current;
    if (!el) return;
    if (open && !el.open) {
      el.showModal();
      keep.current?.focus();
    } else if (!open && el.open) {
      el.close();
    }
  }, [open]);

  return (
    <dialog
      ref={dialog}
      className="idle"
      aria-labelledby="session-warning-title"
      aria-describedby="session-warning-desc"
      onCancel={(e) => {
        // Escape counts as "Keep voting", the safer choice for someone mid-ballot
        e.preventDefault();
        onKeep();
      }}
    >
      <div className="idle-body">
        <span className="idle-icon">
          <ClockIcon size={22} />
        </span>
        {/* SR-04: after the last extension the voter is told no more time is available */}
        {canExtend ? (
          <>
            <h2 id="session-warning-title">Do you need more time?</h2>
            <p id="session-warning-desc">
              Your session ends in <strong className="mono">{formatClock(secondsLeft)}</strong>. Select
              Keep voting to get another {minutes} minutes. If your session ends, any numbers you have
              entered will be cleared.
            </p>
          </>
        ) : (
          <>
            <h2 id="session-warning-title">Your session cannot be extended again</h2>
            <p id="session-warning-desc">
              You have used all the extra time allowed. Your session ends in{" "}
              <strong className="mono">{formatClock(secondsLeft)}</strong>. Submit your ballot before then,
              or any numbers you have entered will be cleared and you will be signed out.
            </p>
          </>
        )}
        <div className="idle-actions">
          <button type="button" className="btn btn-secondary" onClick={onSignOut}>
            Sign out now
          </button>
          <button ref={keep} type="button" className="btn btn-primary" onClick={onKeep}>
            {canExtend ? "Keep voting" : "Continue"}
          </button>
        </div>
      </div>
    </dialog>
  );
}
