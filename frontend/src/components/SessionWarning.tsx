import { useRef } from "react";
import { formatClock } from "../lib/hooks";
import WarningDialog from "./WarningDialog";

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
  const keep = useRef<HTMLButtonElement>(null);

  return (
    <WarningDialog
      open={open}
      titleId="session-warning-title"
      descriptionId="session-warning-desc"
      focusRef={keep}
      // Escape counts as "Keep voting", the safer choice for someone mid-ballot
      onEscape={onKeep}
      // SR-04: after the last extension the voter is told no more time is available
      title={canExtend ? "Do you need more time?" : "Your session cannot be extended again"}
      description={
        canExtend ? (
          <>
            Your session ends in <strong className="mono">{formatClock(secondsLeft)}</strong>. Select
            Keep voting to get another {minutes} minutes. If your session ends, any numbers you have
            entered will be cleared.
          </>
        ) : (
          <>
            You have used all the extra time allowed. Your session ends in{" "}
            <strong className="mono">{formatClock(secondsLeft)}</strong>. Submit your ballot before then,
            or any numbers you have entered will be cleared and you will be signed out.
          </>
        )
      }
      actions={
        <>
          <button type="button" className="btn btn-secondary" onClick={onSignOut}>
            Sign out now
          </button>
          <button ref={keep} type="button" className="btn btn-primary" onClick={onKeep}>
            {canExtend ? "Keep voting" : "Continue"}
          </button>
        </>
      }
    />
  );
}
