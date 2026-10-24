import { useEffect, useRef, type ReactNode, type RefObject } from "react";
import { ClockIcon } from "./Icons";

type Props = {
  open: boolean;
  /** "alertdialog" when the person must respond (SR-15); a plain dialog otherwise (SR-04). */
  role?: "alertdialog";
  titleId: string;
  descriptionId: string;
  title: ReactNode;
  description: ReactNode;
  /** The button that gets focus when the dialog opens. */
  focusRef: RefObject<HTMLButtonElement>;
  /** What Escape counts as: always the safer, keep-going choice. */
  onEscape: () => void;
  actions: ReactNode;
};

/**
 * SR-04, SR-15: the accessible modal warning shared by the session warning (SR-04) and the idle
 * warning (SR-15): a native <dialog> opened with showModal, so focus stays inside it, focus moved to
 * the safer button, and Escape treated as that button rather than as closing the dialog.
 */
export default function WarningDialog({ open, role, titleId, descriptionId, title, description, focusRef, onEscape, actions }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const el = dialog.current;
    if (!el) return;
    if (open && !el.open) {
      el.showModal();
      focusRef.current?.focus();
    } else if (!open && el.open) {
      el.close();
    }
  }, [open, focusRef]);

  return (
    <dialog
      ref={dialog}
      className="idle"
      role={role}
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      onCancel={(e) => {
        e.preventDefault();
        onEscape();
      }}
    >
      <div className="idle-body">
        <span className="idle-icon">
          <ClockIcon size={22} />
        </span>
        <h2 id={titleId}>{title}</h2>
        <p id={descriptionId}>{description}</p>
        <div className="idle-actions">{actions}</div>
      </div>
    </dialog>
  );
}
