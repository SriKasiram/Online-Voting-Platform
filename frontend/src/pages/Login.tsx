import { useEffect, useRef, useState, type FormEvent } from "react";
import { SESSION_MINUTES, SIGN_IN_DIVISION, USE_MOCK } from "../api/client";
import { KeyIcon, ClockIcon, LockIcon, PhoneIcon, UserIcon } from "../components/Icons";
import { ErrorAlert, Notice, Spinner } from "../components/Messages";
import OtpInput from "../components/OtpInput";
import { useFocusOnMount } from "../lib/useFocusOnMount";

type Props = {
  notice: string;
  /** Part 1. Resolves when the server is ready for the code. */
  onSubmitDetails: (username: string, password: string) => Promise<void>;
  /** Part 2. The app moves to the ballot when this resolves. */
  onSubmitCode: (code: string) => Promise<void>;
};

type Part = "details" | "code";

export default function Login({ notice, onSubmitDetails, onSubmitCode }: Props) {
  const detailsHeading = useFocusOnMount<HTMLHeadingElement>();
  const usernameInput = useRef<HTMLInputElement>(null);
  const passwordInput = useRef<HTMLInputElement>(null);
  const codeInput = useRef<HTMLInputElement>(null);

  const [part, setPart] = useState<Part>("details");
  const [moved, setMoved] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [code, setCode] = useState("");
  const [signingInAs, setSigningInAs] = useState("");
  const [showNotice, setShowNotice] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // After switching parts, move focus to where the voter needs to be next
  useEffect(() => {
    if (!moved) return;
    if (part === "code") codeInput.current?.focus();
    else detailsHeading.current?.focus();
  }, [part, moved, detailsHeading]);

  function goTo(next: Part) {
    setError("");
    setPart(next);
    setMoved(true);
  }

  function forgetPassword() {
    // The password is sent once and is not kept on the page
    setPassword("");
    setShowPassword(false);
  }

  async function handleDetails(event: FormEvent) {
    event.preventDefault();
    setError("");
    const name = username.trim();
    if (!name) {
      setError("Enter your username.");
      usernameInput.current?.focus();
      return;
    }
    if (!password) {
      setError("Enter your password.");
      passwordInput.current?.focus();
      return;
    }

    setBusy(true);
    try {
      await onSubmitDetails(name, password);
      forgetPassword();
      setSigningInAs(name);
      setCode("");
      setShowNotice(false);
      setBusy(false);
      goTo("code");
    } catch {
      forgetPassword();
      setError("We could not sign you in. Check your details and try again.");
      setBusy(false);
      passwordInput.current?.focus();
    }
  }

  async function handleCode(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (!/^\d{6}$/.test(code)) {
      setError("Enter the 6-digit code from your authenticator app.");
      codeInput.current?.focus();
      return;
    }

    setBusy(true);
    try {
      await onSubmitCode(code);
    } catch {
      // One message for every failure, so the screen never says which detail was wrong
      setError(
        "We could not sign you in. Check the code and try again. If it keeps failing, select Change and enter your details again.",
      );
      setCode("");
      setBusy(false);
      codeInput.current?.focus();
    }
  }

  function handleChange() {
    setCode("");
    forgetPassword();
    goTo("details");
  }

  const stepClass = moved ? "login-step enter" : "login-step";

  return (
    <section className="screen" aria-labelledby={part === "details" ? "login-title" : "code-title"}>
      <div className="login">
        <div className="login-form">
          {notice && showNotice && <Notice>{notice}</Notice>}

          {part === "details" ? (
            <div className={stepClass}>
              <div className="intro">
                <p className="eyebrow">Part 1 of 2 · Your details</p>
                <h1 id="login-title" ref={detailsHeading} tabIndex={-1}>
                  Sign in to vote
                </h1>
                <p>Enter your voter username and password.</p>
              </div>

              <form className="stack" onSubmit={handleDetails} noValidate>
                <div className="field">
                  <label htmlFor="username">Username</label>
                  <input
                    ref={usernameInput}
                    id="username"
                    className="input"
                    type="text"
                    autoComplete="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                  />
                </div>
                <div className="field">
                  <label htmlFor="password">Password</label>
                  <div className="pw">
                    <input
                      ref={passwordInput}
                      id="password"
                      className="input"
                      type={showPassword ? "text" : "password"}
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                    />
                    <button
                      type="button"
                      className="pw-toggle"
                      aria-label={showPassword ? "Hide password" : "Show password"}
                      onClick={() => setShowPassword((v) => !v)}
                    >
                      {showPassword ? "Hide" : "Show"}
                    </button>
                  </div>
                </div>

                {error && <ErrorAlert>{error}</ErrorAlert>}

                <button type="submit" className="btn btn-primary btn-block" disabled={busy} aria-busy={busy}>
                  {busy ? (
                    <>
                      <Spinner />
                      Signing in
                    </>
                  ) : (
                    "Sign in"
                  )}
                </button>
              </form>
            </div>
          ) : (
            <div className={stepClass}>
              <div className="intro">
                <p className="eyebrow">Part 2 of 2 · Verification</p>
                <h1 id="code-title" tabIndex={-1}>
                  Enter your 6-digit code
                </h1>
                <p>Open your authenticator app and enter the code it shows for this voting service.</p>
              </div>

              <div className="account">
                <span className="avatar" aria-hidden="true">
                  <UserIcon size={16} />
                </span>
                <span className="account-text">
                  <span>Signing in as</span>
                  <strong>{signingInAs}</strong>
                </span>
                <button type="button" className="btn btn-ghost btn-sm" onClick={handleChange} disabled={busy}>
                  Change
                </button>
              </div>

              <form className="stack" onSubmit={handleCode} noValidate>
                <div className="field">
                  <label htmlFor="otp">6-digit code</label>
                  <OtpInput id="otp" value={code} onChange={setCode} describedBy="otp-help" inputRef={codeInput} />
                  <p className="help" id="otp-help">
                    The code changes every 30 seconds.
                  </p>
                </div>

                {error && <ErrorAlert>{error}</ErrorAlert>}

                <button type="submit" className="btn btn-primary btn-block" disabled={busy} aria-busy={busy}>
                  {busy ? (
                    <>
                      <Spinner />
                      Checking code
                    </>
                  ) : (
                    "Verify and continue"
                  )}
                </button>
              </form>
            </div>
          )}

          <div className="hints">
            <p>Using a shared terminal? Sign out when you finish voting.</p>
            {USE_MOCK && (
              <p>Demo: any username and password, then any 6-digit code. Enter 000000 to see the error message.</p>
            )}
          </div>
        </div>

        <aside className="login-context" aria-label="About this ballot">
          <div className="ctx-division">
            <p className="eyebrow">{SIGN_IN_DIVISION.electionName}</p>
            <h2>
              {SIGN_IN_DIVISION.divisionName} <span>{SIGN_IN_DIVISION.stateName}</span>
            </h2>
          </div>

          <div className="mini-sheet" aria-hidden="true">
            <div className="mini-head">
              <span>Ballot paper</span>
              <span>{SIGN_IN_DIVISION.divisionName}</span>
            </div>
            {["2", "1", "3", ""].map((n, i) => (
              <div className="mini-row" key={i}>
                <span className="mini-box">{n}</span>
                <span className="mini-lines">
                  <i />
                  <i />
                </span>
              </div>
            ))}
          </div>

          <ul className="ctx-list">
            <li>
              <h3>Before you start</h3>
            </li>
            <li>
              <span className="ctx-icon">
                <KeyIcon />
              </span>
              <span>Your voter username and password</span>
            </li>
            <li>
              <span className="ctx-icon">
                <PhoneIcon />
              </span>
              <span>Your authenticator app, for the 6-digit code</span>
            </li>
            <li>
              <span className="ctx-icon">
                <ClockIcon />
              </span>
              <span>About 5 minutes to number and check your ballot</span>
            </li>
          </ul>

          <p className="ctx-foot">
            <LockIcon />
            <span>
              Nothing is saved on this device. Your session lasts {SESSION_MINUTES} minutes, and you can
              ask for more time before it ends.
            </span>
          </p>
        </aside>
      </div>
    </section>
  );
}
