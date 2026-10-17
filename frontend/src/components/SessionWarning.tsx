import { useEffect, useRef } from "react";
import { formatClock } from "../lib/useSessionTimer";
import { ClockIcon } from "./Icons";

type Props = {
  open: boolean;
  secondsLeft: number;
  minutes: number;
  onKeep: () => void;
  onSignOut: () => void;
};

/** Asks the voter, one minute before the session ends, whether they need more time. */
export default function SessionWarning({ open, secondsLeft, minutes, onKeep, onSignOut }: Props) {
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
        <h2 id="session-warning-title">Do you need more time?</h2>
        <p id="session-warning-desc">
          Your session ends in <strong className="mono">{formatClock(secondsLeft)}</strong>. Select
          Keep voting to get another {minutes} minutes. If your session ends, any numbers you have
          entered will be cleared.
        </p>
        <div className="idle-actions">
          <button type="button" className="btn btn-secondary" onClick={onSignOut}>
            Sign out now
          </button>
          <button ref={keep} type="button" className="btn btn-primary" onClick={onKeep}>
            Keep voting
          </button>
        </div>
      </div>
    </dialog>
  );
}
