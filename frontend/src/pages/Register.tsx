import { QRCodeSVG } from "qrcode.react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { ApiError, registerAccount, registerConfirm, registerVerify } from "../api/client";
import { ClockIcon, InfoIcon, KeyIcon, LockIcon, PhoneIcon } from "../components/Icons";
import { ErrorAlert, Spinner } from "../components/Messages";
import OtpInput from "../components/OtpInput";
import { useFocusOnMount } from "../lib/hooks";
import { formatSecret, PASSWORD_MIN_LENGTH, passwordProblem, usernameProblem } from "../lib/registerRules";

type Props = {
  /** Back to the sign-in screen without registering. */
  onCancel: () => void;
  /** The account exists. The voter signs in normally from here. */
  onComplete: () => void;
};

type Step = "details" | "account" | "authenticator";

const VERIFY_FAILED =
  "We could not verify these details. Check them against your enrolment letter and try again.";

/** Why the registration cannot go on, or null when the voter can still fix the problem. */
function endedReason(error: unknown): string | null {
  switch (error instanceof ApiError ? error.code : undefined) {
    case "too_many_attempts":
      return "too many codes did not match";
    case "already_registered":
      return "this person is already registered";
    case "registration_session_invalid":
      return "it was not finished within 10 minutes";
    default:
      return null;
  }
}

function accountMessage(error: unknown): string {
  switch (error instanceof ApiError ? error.code : undefined) {
    case "username_taken":
      return "That username is already in use. Choose another.";
    case "username_invalid":
      return "Use 3 to 32 letters, digits, dots or underscores.";
    case "password_too_short":
      return `Use at least ${PASSWORD_MIN_LENGTH} characters.`;
    case "password_is_username":
      return "Your password must not be your username.";
    default:
      return "Your account could not be set up. Try again.";
  }
}

export default function Register({ onCancel, onComplete }: Props) {
  const detailsHeading = useFocusOnMount<HTMLHeadingElement>();
  const accountHeading = useRef<HTMLHeadingElement>(null);
  const authenticatorHeading = useRef<HTMLHeadingElement>(null);
  const endedHeading = useRef<HTMLHeadingElement>(null);
  const codeInput = useRef<HTMLInputElement>(null);

  const [step, setStep] = useState<Step>("details");
  const [moved, setMoved] = useState(false);
  const [givenName, setGivenName] = useState("");
  const [surname, setSurname] = useState("");
  const [dateOfBirth, setDateOfBirth] = useState("");
  const [postcode, setPostcode] = useState("");
  const [enrolmentCode, setEnrolmentCode] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  // The second factor's secret. Held only while step 3 is on screen.
  const [authenticator, setAuthenticator] = useState<{ uri: string; secret: string } | null>(null);
  const [code, setCode] = useState("");
  const [ended, setEnded] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // After each change of step, move focus to the new heading
  useEffect(() => {
    if (ended) endedHeading.current?.focus();
    else if (!moved) return;
    else if (step === "account") accountHeading.current?.focus();
    else if (step === "authenticator") authenticatorHeading.current?.focus();
    else detailsHeading.current?.focus();
  }, [step, moved, ended, detailsHeading]);

  function goTo(next: Step) {
    setError("");
    setStep(next);
    setMoved(true);
  }

  function forgetPassword() {
    // The password is sent once and is not kept on the page
    setPassword("");
    setShowPassword(false);
  }

  function end(reason: string) {
    setAuthenticator(null);
    setCode("");
    setEnded(reason);
  }

  async function handleDetails(event: FormEvent) {
    event.preventDefault();
    setError("");
    if ([givenName, surname, dateOfBirth, postcode, enrolmentCode].some((value) => !value.trim())) {
      setError("Fill in every field.");
      return;
    }

    setBusy(true);
    try {
      await registerVerify({ givenName, surname, dateOfBirth, postcode, enrolmentCode });
      // Personal details are not needed after this step
      setGivenName("");
      setSurname("");
      setDateOfBirth("");
      setPostcode("");
      setEnrolmentCode("");
      setBusy(false);
      goTo("account");
    } catch {
      // One message for every failure, so the screen never reveals who is on the roll
      setError(VERIFY_FAILED);
      setBusy(false);
    }
  }

  async function handleAccount(event: FormEvent) {
    event.preventDefault();
    setError("");
    const name = username.trim();
    const problem = usernameProblem(name) || passwordProblem(password, name);
    if (problem) {
      setError(problem);
      return;
    }

    setBusy(true);
    try {
      const result = await registerAccount(name, password);
      forgetPassword();
      setAuthenticator({ uri: result.otpauthUri, secret: result.secret });
      setCode("");
      setBusy(false);
      goTo("authenticator");
    } catch (failure) {
      forgetPassword();
      setBusy(false);
      const reason = endedReason(failure);
      if (reason) end(reason);
      else setError(accountMessage(failure));
    }
  }

  async function handleConfirm(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (!/^\d{6}$/.test(code)) {
      setError("Enter the 6-digit code from your authenticator app.");
      codeInput.current?.focus();
      return;
    }

    setBusy(true);
    try {
      await registerConfirm(code);
      setAuthenticator(null);
      setCode("");
      onComplete();
    } catch (failure) {
      setCode("");
      setBusy(false);
      const reason = endedReason(failure);
      if (reason) {
        end(reason);
      } else if (failure instanceof ApiError && failure.code === "username_taken") {
        // Someone else finished with this username first: choose another
        setAuthenticator(null);
        goTo("account");
        setError("Someone has just taken that username. Choose another.");
      } else {
        setError("That code did not match. Check that the clock on your phone is right, then enter the newest code.");
        codeInput.current?.focus();
      }
    }
  }

  const stepClass = moved ? "login-step enter" : "login-step";
  const leaveWarning = (
    <p className="help">Leaving now ends this registration, and your enrolment code cannot be used again.</p>
  );
  const backButton = (
    <button type="button" className="btn btn-ghost btn-sm" onClick={onCancel} disabled={busy}>
      Back to sign in
    </button>
  );

  return (
    <section className="screen" aria-label="Register to vote">
      <div className="login">
        <div className="login-form">
          {ended ? (
            <div className="login-step enter">
              <div className="intro">
                <h1 ref={endedHeading} tabIndex={-1}>
                  Registration ended
                </h1>
                <p>
                  This registration has ended because {ended}. Your enrolment code has been used, so you need a new
                  one to register. Ask the electoral commission, or a polling official, for help.
                </p>
              </div>
              <button type="button" className="btn btn-primary btn-block" onClick={onCancel}>
                Back to sign in
              </button>
            </div>
          ) : step === "details" ? (
            <div className={stepClass}>
              <div className="intro">
                <p className="eyebrow">Step 1 of 3 · Your details</p>
                <h1 ref={detailsHeading} tabIndex={-1}>
                  Register to vote
                </h1>
                <p>Enter your details exactly as they appear on the electoral roll.</p>
              </div>

              <form className="stack" onSubmit={handleDetails} noValidate>
                <div className="field">
                  <label htmlFor="given-name">Given name</label>
                  <input
                    id="given-name"
                    className="input"
                    autoComplete="given-name"
                    value={givenName}
                    onChange={(e) => setGivenName(e.target.value)}
                    required
                  />
                </div>
                <div className="field">
                  <label htmlFor="surname">Surname</label>
                  <input
                    id="surname"
                    className="input"
                    autoComplete="family-name"
                    value={surname}
                    onChange={(e) => setSurname(e.target.value)}
                    required
                  />
                </div>
                <div className="field">
                  <label htmlFor="date-of-birth">Date of birth</label>
                  <input
                    id="date-of-birth"
                    className="input"
                    type="date"
                    autoComplete="bday"
                    value={dateOfBirth}
                    onChange={(e) => setDateOfBirth(e.target.value)}
                    required
                  />
                </div>
                <div className="field">
                  <label htmlFor="postcode">Postcode</label>
                  <input
                    id="postcode"
                    className="input input-short"
                    inputMode="numeric"
                    autoComplete="postal-code"
                    maxLength={4}
                    value={postcode}
                    onChange={(e) => setPostcode(e.target.value.replace(/\D/g, ""))}
                    required
                  />
                </div>
                <div className="field">
                  <label htmlFor="enrolment-code">Enrolment code</label>
                  <input
                    id="enrolment-code"
                    className="input mono"
                    autoComplete="off"
                    spellCheck={false}
                    value={enrolmentCode}
                    onChange={(e) => setEnrolmentCode(e.target.value.toUpperCase())}
                    aria-describedby="enrolment-code-help"
                    required
                  />
                  <p className="help" id="enrolment-code-help">
                    Enter the one-time enrolment code sent to you by post or email. For this prototype, enter the
                    code assigned to you in the README file.
                  </p>
                </div>

                {error && <ErrorAlert>{error}</ErrorAlert>}

                <button type="submit" className="btn btn-primary btn-block" disabled={busy} aria-busy={busy}>
                  {busy ? (
                    <>
                      <Spinner />
                      Checking details
                    </>
                  ) : (
                    "Continue"
                  )}
                </button>
              </form>
              {backButton}
            </div>
          ) : step === "account" ? (
            <div className={stepClass}>
              <div className="intro">
                <p className="eyebrow">Step 2 of 3 · Your account</p>
                <h1 ref={accountHeading} tabIndex={-1}>
                  Choose a username and password
                </h1>
                <p>You will sign in with these, and a code from your authenticator app.</p>
              </div>

              <form className="stack" onSubmit={handleAccount} noValidate>
                <div className="field">
                  <label htmlFor="new-username">Username</label>
                  <input
                    id="new-username"
                    className="input"
                    autoComplete="username"
                    spellCheck={false}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    aria-describedby="new-username-help"
                    required
                  />
                  <p className="help" id="new-username-help">
                    3 to 32 letters, digits, dots or underscores.
                  </p>
                </div>
                <div className="field">
                  <label htmlFor="new-password">Password</label>
                  <div className="pw">
                    <input
                      id="new-password"
                      className="input"
                      type={showPassword ? "text" : "password"}
                      autoComplete="new-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      aria-describedby="new-password-help"
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
                  <p className="help" id="new-password-help">
                    At least {PASSWORD_MIN_LENGTH} characters, and not your username. A few unrelated words make a
                    strong password.
                  </p>
                </div>

                {error && <ErrorAlert>{error}</ErrorAlert>}

                <button type="submit" className="btn btn-primary btn-block" disabled={busy} aria-busy={busy}>
                  {busy ? (
                    <>
                      <Spinner />
                      Setting up
                    </>
                  ) : (
                    "Continue"
                  )}
                </button>
              </form>
              {leaveWarning}
              {backButton}
            </div>
          ) : (
            <div className={stepClass}>
              <div className="intro">
                <p className="eyebrow">Step 3 of 3 · Authenticator app</p>
                <h1 ref={authenticatorHeading} tabIndex={-1}>
                  Set up your authenticator app
                </h1>
                <p>
                  Open an authenticator app on your phone, such as Google Authenticator or Microsoft
                  Authenticator, and add an account by scanning this QR code.
                </p>
              </div>

              <div className="notice">
                <InfoIcon />
                <span>Register on your own device or in private, the QR code gives access to your second factor.</span>
              </div>

              {authenticator && (
                <div className="authenticator">
                  <div className="qr-box">
                    <QRCodeSVG
                      value={authenticator.uri}
                      size={176}
                      marginSize={1}
                      role="img"
                      aria-label="QR code to add this account to your authenticator app"
                    />
                  </div>
                  <div className="field">
                    <span className="label">Or type this setup key into the app</span>
                    <p className="secret-key">{formatSecret(authenticator.secret)}</p>
                  </div>
                </div>
              )}

              <form className="stack" onSubmit={handleConfirm} noValidate>
                <div className="field">
                  <label htmlFor="register-otp">6-digit code from the app</label>
                  <OtpInput
                    id="register-otp"
                    value={code}
                    onChange={setCode}
                    describedBy="register-otp-help"
                    inputRef={codeInput}
                  />
                  <p className="help" id="register-otp-help">
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
                    "Finish registration"
                  )}
                </button>
              </form>
              {leaveWarning}
              {backButton}
            </div>
          )}
        </div>

        <aside className="login-context" aria-label="About registering">
          <div className="ctx-division">
            <p className="eyebrow">House of Representatives</p>
            <h2>
              Register to vote <span>once, before you sign in</span>
            </h2>
          </div>

          <ul className="ctx-list">
            <li>
              <h3>You will need</h3>
            </li>
            <li>
              <span className="ctx-icon">
                <KeyIcon />
              </span>
              <span>Your details as they appear on the electoral roll, and your one-time enrolment code</span>
            </li>
            <li>
              <span className="ctx-icon">
                <PhoneIcon />
              </span>
              <span>An authenticator app on your phone</span>
            </li>
            <li>
              <span className="ctx-icon">
                <ClockIcon />
              </span>
              <span>About 5 minutes. Finish within 10 minutes of starting.</span>
            </li>
          </ul>

          <p className="ctx-foot">
            <LockIcon />
            <span>Nothing is saved on this device. Your enrolment code works only once.</span>
          </p>
        </aside>
      </div>
    </section>
  );
}
