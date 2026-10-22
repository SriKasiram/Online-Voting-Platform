import { useState, type FormEvent } from "react";
import { SESSION_MINUTES } from "../api/client";
import { staffLogin, staffLogout, staffVerify } from "../api/staffClient";
import Layout from "../components/Layout";
import { ErrorAlert, Notice, Spinner } from "../components/Messages";
import OtpInput from "../components/OtpInput";
import { useFocusOnMount, useSessionTimer } from "../lib/hooks";

// SR-06: one message for every failure, so the page never says which detail was wrong
const FAILED = "Sign in failed";
const ENDED = "Your session has ended. Sign in again.";
const ROLE_NAMES: Record<string, string> = { polling_official: "Polling official", auditor: "Auditor" };
const timeFormat = new Intl.DateTimeFormat("en-AU", { timeStyle: "short" });

type View = { name: "details" } | { name: "code" } | { name: "signed-in"; role: string; endsAt: Date };

// SR-06: the staff sign-in page (staff.html). Password, then the authenticator code, then a
// 10-minute session that cannot be extended. Only the view is kept, in memory (no browser
// storage), and the page never calls an admin route.
export default function StaffApp() {
  const [view, setView] = useState<View>({ name: "details" });
  const [notice, setNotice] = useState("");
  const signedIn = view.name === "signed-in";
  // SR-06: counts down the fixed session. Nothing restarts it: staff sessions cannot be extended.
  const session = useSessionTimer(signedIn, SESSION_MINUTES, () => void signOut(ENDED));

  async function signOut(message: string) {
    setView({ name: "details" });
    setNotice(message);
    try {
      await staffLogout();
    } catch {
      // The server session ends on its own
    }
  }

  return (
    <Layout
      step={0}
      steps={false}
      voterName={null}
      sessionSecondsLeft={signedIn ? session.secondsLeft : null}
      onSignOut={() => void signOut("")}
    >
      <section className="screen" aria-labelledby="staff-title">
        <div className="login">
          <div className="login-form">
            <div className="intro">
              <p className="eyebrow">Election staff only</p>
              <h1 id="staff-title">Staff access</h1>
            </div>
            {notice && <Notice>{notice}</Notice>}
            {view.name === "details" && (
              <DetailsStep
                onDone={() => {
                  setNotice("");
                  setView({ name: "code" });
                }}
              />
            )}
            {view.name === "code" && (
              <CodeStep
                onDone={(role) =>
                  setView({ name: "signed-in", role, endsAt: new Date(Date.now() + SESSION_MINUTES * 60_000) })
                }
                onStartAgain={() => void signOut("")}
              />
            )}
            {view.name === "signed-in" && (
              <SignedIn role={view.role} endsAt={view.endsAt} onSignOut={() => void signOut("You have signed out.")} />
            )}
          </div>
        </div>
      </section>
    </Layout>
  );
}

// SR-06: view 1, username and password (SR-01 password step)
function DetailsStep({ onDone }: { onDone: () => void }) {
  const first = useFocusOnMount<HTMLInputElement>();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      await staffLogin(username.trim(), password);
      setPassword("");
      onDone();
    } catch {
      // The password is sent once and is not kept on the page
      setPassword("");
      setError(FAILED);
      setBusy(false);
    }
  }

  return (
    <form className="stack" onSubmit={submit} noValidate>
      <p>Sign in with your staff username and password.</p>
      <div className="field">
        <label htmlFor="staff-username">Username</label>
        <input
          ref={first}
          id="staff-username"
          className="input"
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
      </div>
      <div className="field">
        <label htmlFor="staff-password">Password</label>
        <input
          id="staff-password"
          className="input"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </div>
      {error && <ErrorAlert>{error}</ErrorAlert>}
      <button type="submit" className="btn btn-primary btn-block" disabled={busy} aria-busy={busy}>
        {busy ? (
          <>
            <Spinner />
            Checking
          </>
        ) : (
          "Continue"
        )}
      </button>
    </form>
  );
}

// SR-06: view 2, the code from the authenticator app (SR-01 TOTP step). No admin access without it.
function CodeStep({ onDone, onStartAgain }: { onDone: (role: string) => void; onStartAgain: () => void }) {
  const first = useFocusOnMount<HTMLInputElement>();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      onDone(await staffVerify(code));
    } catch {
      setCode("");
      setError(FAILED);
      setBusy(false);
      first.current?.focus();
    }
  }

  return (
    <form className="stack" onSubmit={submit} noValidate>
      <p>Enter the 6-digit code from your authenticator app.</p>
      <div className="field">
        <label htmlFor="staff-code">6-digit code</label>
        <OtpInput id="staff-code" value={code} onChange={setCode} describedBy="staff-code-help" inputRef={first} />
        <p className="help" id="staff-code-help">
          The code changes every 30 seconds.
        </p>
      </div>
      {error && <ErrorAlert>{error}</ErrorAlert>}
      <button type="submit" className="btn btn-primary btn-block" disabled={busy} aria-busy={busy}>
        {busy ? (
          <>
            <Spinner />
            Checking
          </>
        ) : (
          "Sign in"
        )}
      </button>
      <button type="button" className="btn btn-secondary btn-block" onClick={onStartAgain} disabled={busy}>
        Start again
      </button>
    </form>
  );
}

// SR-06: view 3, signed in: the role, when the session ends, and sign out
function SignedIn({ role, endsAt, onSignOut }: { role: string; endsAt: Date; onSignOut: () => void }) {
  const first = useFocusOnMount<HTMLButtonElement>();

  return (
    <div className="stack">
      <p>
        Signed in as <strong>{ROLE_NAMES[role] ?? role}</strong>.
      </p>
      <p>
        Your session ends at <strong>{timeFormat.format(endsAt)}</strong> ({SESSION_MINUTES} minutes, cannot be
        extended).
      </p>
      <button ref={first} type="button" className="btn btn-primary btn-block" onClick={onSignOut}>
        Sign out
      </button>
    </div>
  );
}
