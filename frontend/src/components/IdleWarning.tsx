import { useEffect, useRef } from "react";
import { ClockIcon } from "./Icons";

type Props = {
  open: boolean;
  secondsLeft: number;
  onStillHere: () => void;
};

/**
 * SR-15: asks an elector who has stopped using the screen whether they are still there, before the
 * session is ended for them. It looks like the SR-04 session warning (dialog.idle), but is an
 * alertdialog with one button, because the elector must respond or lose the session.
 */
export default function IdleWarning({ open, secondsLeft, onStillHere }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const el = dialog.current;
    if (!el) return;
    if (open && !el.open) {
      el.showModal();
      button.current?.focus();
    } else if (!open && el.open) {
      el.close();
    }
  }, [open]);

  return (
    <dialog
      ref={dialog}
      className="idle"
      role="alertdialog"
      aria-labelledby="idle-warning-title"
      aria-describedby="idle-warning-desc"
      onCancel={(e) => {
        // SR-15: Escape means someone is there, so it counts as "I'm still here"
        e.preventDefault();
        onStillHere();
      }}
    >
      <div className="idle-body">
        <span className="idle-icon">
          <ClockIcon size={22} />
        </span>
        <h2 id="idle-warning-title">Are you still there?</h2>
        <p id="idle-warning-desc">
          This session will end in <strong className="mono">{secondsLeft}</strong>{" "}
          {secondsLeft === 1 ? "second" : "seconds"} to protect your vote.
        </p>
        <div className="idle-actions">
          <button ref={button} type="button" className="btn btn-primary" onClick={onStillHere}>
            I'm still here
          </button>
        </div>
      </div>
    </dialog>
  );
}
