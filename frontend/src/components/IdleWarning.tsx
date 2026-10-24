import { useRef } from "react";
import WarningDialog from "./WarningDialog";

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
  const button = useRef<HTMLButtonElement>(null);

  return (
    <WarningDialog
      open={open}
      role="alertdialog"
      titleId="idle-warning-title"
      descriptionId="idle-warning-desc"
      focusRef={button}
      // SR-15: Escape means someone is there, so it counts as "I'm still here"
      onEscape={onStillHere}
      title="Are you still there?"
      description={
        <>
          This session will end in <strong className="mono">{secondsLeft}</strong>{" "}
          {secondsLeft === 1 ? "second" : "seconds"} to protect your vote.
        </>
      }
      actions={
        <button ref={button} type="button" className="btn btn-primary" onClick={onStillHere}>
          I'm still here
        </button>
      }
    />
  );
}
