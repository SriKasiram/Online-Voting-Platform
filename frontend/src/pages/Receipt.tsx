import { useEffect, useRef, useState } from "react";
import { CopyIcon } from "../components/Icons";
import { useFocusOnMount } from "../lib/hooks";
import { countdownAnnouncement, startReceiptCountdown } from "../lib/receiptCountdown";

export type ReceiptDetails = {
  receiptId: string;
  acceptedAt: Date;
  electionName: string;
  divisionName: string;
};

type Props = {
  receipt: ReceiptDetails;
  // SR-15: VITE_RECEIPT_SECONDS, kept in step with the backend's POST_BALLOT_SESSION_SECONDS
  seconds: number;
  // SR-15: both end the session through the terminal reset: Done, or the countdown reaching 0
  onDone: () => void;
  onTimeout: () => void;
};

const acceptedFormat = new Intl.DateTimeFormat("en-AU", { dateStyle: "long", timeStyle: "short" });

export default function Receipt({ receipt, seconds, onDone, onTimeout }: Props) {
  const heading = useFocusOnMount<HTMLHeadingElement>();
  const codeText = useRef<HTMLParagraphElement>(null);
  const [secondsLeft, setSecondsLeft] = useState(seconds);
  const [copyLabel, setCopyLabel] = useState("Copy code");

  const timeout = useRef(onTimeout);
  timeout.current = onTimeout;

  // SR-15: starts when the receipt appears, so every elector gets the same time to note the reference
  useEffect(
    () => startReceiptCountdown({ seconds, onTick: setSecondsLeft, onTimeout: () => timeout.current() }),
    [seconds],
  );

  useEffect(() => {
    if (copyLabel === "Copy code") return;
    const reset = window.setTimeout(() => setCopyLabel("Copy code"), 2500);
    return () => window.clearTimeout(reset);
  }, [copyLabel]);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(receipt.receiptId);
      setCopyLabel("Copied");
    } catch {
      // Clipboard blocked: select the code so the voter can copy it themselves
      const node = codeText.current;
      const selection = window.getSelection();
      if (node && selection) {
        const range = document.createRange();
        range.selectNodeContents(node);
        selection.removeAllRanges();
        selection.addRange(range);
      }
      setCopyLabel("Selected. Press Ctrl+C to copy");
    }
  }

  return (
    <section className="screen" aria-labelledby="receipt-title">
      <div className="receipt">
        <div className="receipt-hero">
          <svg className="tick" viewBox="0 0 72 72" aria-hidden="true" focusable="false">
            <circle className="tick-bg" cx="36" cy="36" r="34" />
            <path className="tick-path" d="M22 37.5l9.5 9.5L51 27.5" />
          </svg>
          <h1 id="receipt-title" ref={heading} tabIndex={-1}>
            Your ballot has been accepted
          </h1>
          <p>Thank you for voting.</p>
        </div>

        <div className="code-box">
          <p className="eyebrow">Receipt code</p>
          <p className="code" ref={codeText}>
            {receipt.receiptId}
          </p>
          <button type="button" className="btn btn-secondary btn-sm" onClick={handleCopy}>
            <CopyIcon size={16} />
            <span aria-live="polite">{copyLabel}</span>
          </button>
        </div>

        <dl className="facts">
          <dt>Accepted</dt>
          <dd>{acceptedFormat.format(receipt.acceptedAt)}</dd>
          <dt>Ballot</dt>
          <dd>{receipt.electionName}</dd>
          <dt>Division</dt>
          <dd>{receipt.divisionName}</dd>
        </dl>

        <p className="fineprint">
          Keep this code if you want a record that your ballot was accepted. The code does not show how
          you voted.
        </p>

        <div className="signout-timer">
          {/* SR-15: updated every second, but not a live region, so screen readers are not told every second */}
          <p>
            This screen will clear in <strong className="mono">{secondsLeft}</strong>{" "}
            {secondsLeft === 1 ? "second" : "seconds"}.
          </p>
          {/* SR-15: announced politely at 30, 10 and 5 seconds only */}
          <p className="sr-only" aria-live="polite">
            {countdownAnnouncement(secondsLeft)}
          </p>
          <div className="track" aria-hidden="true">
            <div className="track-fill" style={{ width: `${(secondsLeft / seconds) * 100}%` }} />
          </div>
        </div>

        <button type="button" className="btn btn-primary btn-block" onClick={onDone}>
          Done
        </button>
      </div>
    </section>
  );
}
