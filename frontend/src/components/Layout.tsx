import { useEffect, useState, type ReactNode } from "react";
import { formatClock } from "../lib/hooks";
import { ClockIcon } from "./Icons";

/** Up to two capital letters for the signed-in voter's badge. */
function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => word[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

type Props = {
  /** 0 to 3, matching STEPS below. */
  step: number;
  voterName: string | null;
  /** Shown in the top bar while a ballot is open. Null hides the timer. */
  sessionSecondsLeft: number | null;
  onSignOut: () => void;
  children: ReactNode;
  // SR-06: false hides the voting steps, for the staff sign-in page. The voter app leaves it out.
  steps?: boolean;
};

const STEPS = [
  { long: "Sign in", short: "Sign in" },
  { long: "Number your ballot", short: "Number" },
  { long: "Check and submit", short: "Check" },
  { long: "Receipt", short: "Receipt" },
];

type TextSize = "md" | "lg" | "xl";

const TEXT_SIZES: { size: TextSize; label: string }[] = [
  { size: "md", label: "Standard text size" },
  { size: "lg", label: "Large text size" },
  { size: "xl", label: "Largest text size" },
];

function BrandMark() {
  return (
    <svg width="30" height="30" viewBox="0 0 28 28" aria-hidden="true" focusable="false">
      <rect className="bm-box" x="1" y="1" width="26" height="26" rx="7" />
      <path className="bm-slot" d="M9 7.5h10" fill="none" strokeWidth="2.6" strokeLinecap="round" />
      <path
        className="bm-tick"
        d="M8.5 15.5l3.6 3.6L19.5 12"
        fill="none"
        strokeWidth="2.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function Layout({ step, voterName, sessionSecondsLeft, onSignOut, children, steps = true }: Props) {
  const [textSize, setTextSize] = useState<TextSize>("md");

  useEffect(() => {
    document.documentElement.dataset.text = textSize;
  }, [textSize]);

  return (
    <div className="page">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>

      <header className="topbar">
        <div className="wrap topbar-row">
          <div className="brand">
            <BrandMark />
            <span className="brand-name">Online Voting</span>
            <span className="brand-tag">Prototype</span>
          </div>

          <div className="tools">
            <div className="textsize" role="group" aria-label="Text size">
              {TEXT_SIZES.map(({ size, label }) => (
                <button
                  key={size}
                  type="button"
                  aria-label={label}
                  aria-pressed={textSize === size}
                  onClick={() => setTextSize(size)}
                >
                  A
                </button>
              ))}
            </div>

            {sessionSecondsLeft !== null && (
              <span
                className={sessionSecondsLeft <= 120 ? "session is-low" : "session"}
                title="Time left in your session"
              >
                <ClockIcon size={16} />
                <span className="session-label">Session</span>
                <span className="session-time">{formatClock(sessionSecondsLeft)}</span>
              </span>
            )}

            {voterName && (
              <div className="user">
                <span className="avatar" aria-hidden="true">
                  {initials(voterName)}
                </span>
                <span className="user-name">{voterName}</span>
                <button type="button" className="btn btn-secondary btn-sm" onClick={onSignOut}>
                  Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* SR-06: shown only when steps is true (the voter app) */}
      {steps && (
        <nav className="wrap steps" aria-label="Voting steps">
          <ol>
            {STEPS.map((s, i) => {
              const state = i < step ? "done" : i === step ? "current" : "todo";
              return (
                <li key={s.long} data-state={state} aria-current={i === step ? "step" : undefined}>
                  <span className="step-bar" />
                  <span className="step-label">
                    <span className="step-num">{String(i + 1).padStart(2, "0")}</span>
                    <span className="step-name">
                      <span className="long">{s.long}</span>
                      <span className="short">{s.short}</span>
                    </span>
                    {state === "done" && <span className="sr-only">, completed</span>}
                  </span>
                </li>
              );
            })}
          </ol>
        </nav>
      )}

      <main id="main" className="wrap">
        {children}
      </main>

      <footer className="foot">
        <div className="wrap foot-row">
          <span>Need help? Ask a polling official.</span>
        </div>
      </footer>
    </div>
  );
}
