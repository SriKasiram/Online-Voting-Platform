import { useCallback, useEffect, useMemo, useState } from "react";
import { flushSync } from "react-dom";
import {
  ApiError,
  SESSION_MINUTES,
  extendSession,
  getBallot,
  login,
  logout,
  submitBallot,
  verifyCode,
} from "./api/client";
import type { BallotDefinition } from "./api/types";
import IdleWarning from "./components/IdleWarning";
import Layout from "./components/Layout";
import SessionWarning from "./components/SessionWarning";
import type { Ranking } from "./lib/ballotRules";
// SR-09: one place that clears the ballot, and the pagehide/pageshow handling
import { acceptBallot, clearBallotState, endSession, registerPageLifecycle } from "./lib/clientSession";
import { useSessionTimer } from "./lib/hooks";
// SR-15: the terminal reset, its settings and the idle timer
import { warningToShow } from "./lib/idleController";
import { createTerminalReset, sessionEndHandlers } from "./lib/terminalReset";
import { TERMINAL } from "./lib/terminalSettings";
import { useIdleReset } from "./lib/useIdleReset";
import Ballot from "./pages/Ballot";
import Login from "./pages/Login";
import Receipt, { type ReceiptDetails } from "./pages/Receipt";
import Register from "./pages/Register";
import Review from "./pages/Review";

type Screen = "login" | "register" | "ballot" | "review" | "receipt";

const STEP: Record<Screen, number> = { login: 0, register: 0, ballot: 1, review: 2, receipt: 3 };

/** The "Do you need more time?" box appears this many seconds before the session ends. */
const WARN_SECONDS = 60;

const SESSION_ENDED = "Your session ended, so you were signed out. Sign in again to vote.";
const REGISTERED = "Registration complete. Sign in with your username, password and authenticator code.";

/** Why a signed-in account was not given a ballot, in the voter's terms. */
function noBallotMessage(error: unknown): string {
  switch (error instanceof ApiError ? error.code : undefined) {
    case "already_voted":
      return "You have already voted in this election. Each voter can vote once.";
    case "not_enrolled":
      return "You are not enrolled to vote in this election. Ask a polling official for help.";
    case "not_a_voter":
      return "This account is for election officials and cannot vote.";
    case "no_open_election":
      return "No election is open for voting right now.";
    default:
      return "Your ballot could not be loaded. Sign in again, or ask a polling official for help.";
  }
}

export default function App() {
  const [screen, setScreen] = useState<Screen>("login");
  const [voterName, setVoterName] = useState<string | null>(null);
  const [ballot, setBallot] = useState<BallotDefinition | null>(null);
  const [ranking, setRanking] = useState<Ranking>([]);
  const [receipt, setReceipt] = useState<ReceiptDetails | null>(null);
  const [notice, setNotice] = useState("");
  // Changing this gives the sign-in form a fresh start, so nothing typed is left behind
  const [loginKey, setLoginKey] = useState(0);
  // SR-04: "refused" once the server says the session cannot be extended again,
  // "acknowledged" once the voter has closed that warning
  const [extension, setExtension] = useState<"allowed" | "refused" | "acknowledged">("allowed");

  // SR-09: the ballot paper, its token and the ranking, cleared only through clearBallotState
  const clearBallot = useCallback(() => clearBallotState({ setBallot, setRanking }), []);

  // SR-15: everything the app holds about this elector, cleared before the server is even told,
  // in case the navigation that follows is slow
  const clearAll = useCallback(() => {
    clearBallot();
    setReceipt(null);
    setVoterName(null);
    setNotice("");
    setExtension("allowed");
    setLoginKey((key) => key + 1);
    setScreen("login");
  }, [clearBallot]);

  // SR-15: made once per page load, so its guard lets only the first reset run. The full
  // navigation discards memory, and replace() stops Back from returning to the old session.
  const reset = useMemo(
    () =>
      createTerminalReset({
        clear: clearAll,
        logout,
        navigate: () => window.location.replace(import.meta.env.BASE_URL),
        logoutTimeoutMs: TERMINAL.logoutTimeoutMs,
      }),
    [clearAll],
  );
  const ends = useMemo(() => sessionEndHandlers((reason) => void reset(reason)), [reset]);

  // Returns to the sign-in form with a message, for the cases where the voter must be told why
  // they cannot vote. SR-15: no ballot is open by then, and the idle reset still applies there.
  const returnToSignIn = useCallback(
    async (message: string) => {
      setScreen("login");
      setVoterName(null);
      setReceipt(null);
      setNotice(message);
      setLoginKey((key) => key + 1);
      setExtension("allowed"); // SR-04: the next sign in starts with its extensions unused
      // SR-09: the selections go first, then the server is told
      await endSession(clearBallot, logout);
    },
    [clearBallot],
  );

  // SR-09: pagehide clears the ballot at once (the browser may freeze the page straight after),
  // and a page restored from the back/forward cache reloads. Removed when the app unmounts.
  useEffect(() => registerPageLifecycle(window, () => flushSync(clearBallot)), [clearBallot]);

  // Runs only while someone is signed in. Registration has its own 10-minute limit on the server.
  const signedIn = screen === "ballot" || screen === "review" || screen === "receipt";
  // SR-15: the end of the SR-04 session resets the terminal like any other end
  const session = useSessionTimer(signedIn, SESSION_MINUTES, ends.sessionExpired);

  // SR-15: every elector screen except the receipt, which has its own countdown
  const idle = useIdleReset(screen !== "receipt", TERMINAL.idleSeconds, TERMINAL.idleWarningSeconds, ends.idleTimeout);

  // Leaving registration, finished or not, starts the sign-in form afresh.
  // Everything typed into registration lived in the Register screen and goes with it.
  function showLogin(message: string) {
    setNotice(message);
    setLoginKey((key) => key + 1);
    setScreen("login");
  }

  const ballotOpen = screen === "ballot" || screen === "review";
  // SR-04: once the voter has read that no more time is available, the warning stays closed
  const warningOpen =
    ballotOpen && session.secondsLeft > 0 && session.secondsLeft <= WARN_SECONDS && extension !== "acknowledged";
  // SR-15: never both warnings at once; the one that ends sooner is shown
  const shownWarning = warningToShow(warningOpen ? session.secondsLeft : null, idle.warningSecondsLeft);

  async function handleKeepVoting() {
    // SR-04: after a refusal the button only closes the warning, and the session ends on time
    if (extension !== "allowed") {
      setExtension("acknowledged");
      return;
    }
    try {
      await extendSession();
      // SR-04: restart the timer only once the server has issued the new session
      session.extend();
    } catch (error) {
      // SR-04: limit reached: say so, and let the time that is left run out
      if (error instanceof ApiError && error.code === "extension_limit") {
        setExtension("refused");
        return;
      }
      // SR-15: a 401 means the session is gone, so the terminal resets
      if (ends.apiError(error)) return;
      void returnToSignIn(SESSION_ENDED);
    }
  }

  async function handleCode(code: string) {
    // A wrong code throws here, and the sign-in form shows its usual message
    const { displayName } = await verifyCode(code);
    let definition: BallotDefinition;
    try {
      definition = await getBallot();
    } catch (error) {
      // SR-15: a 401 means the session is gone, so the terminal resets
      if (ends.apiError(error)) return;
      // Signed in, but this account gets no ballot. End the session and say why.
      void returnToSignIn(noBallotMessage(error));
      return;
    }
    setNotice("");
    setVoterName(displayName);
    setBallot(definition);
    setRanking([]);
    setScreen("ballot");
  }

  async function handleSubmit(ballotToken: string, ranked: number[]) {
    if (!ballot) throw new Error("No ballot is open");
    let receiptId: string;
    try {
      ({ receiptId } = await submitBallot(ballotToken, ranked));
    } catch (error) {
      // SR-09: session lost, so the ballot goes. SR-15: through the terminal reset.
      if (ends.apiError(error)) return;
      if (error instanceof ApiError && error.code === "already_voted") {
        void returnToSignIn(noBallotMessage(error));
        return;
      }
      // Anything else: the review screen offers to try again
      throw error;
    }
    // SR-09: selections are cleared as soon as the ballot is accepted, and the receipt holds none
    setReceipt(acceptBallot(receiptId, ballot, { setBallot, setRanking }));
    setScreen("receipt");
  }

  return (
    <Layout
      step={STEP[screen]}
      voterName={voterName}
      sessionSecondsLeft={ballotOpen ? session.secondsLeft : null}
      // SR-15: signing out resets the terminal like finishing does
      onSignOut={ends.signOut}
    >
      {screen === "login" && (
        <Login
          key={loginKey}
          notice={notice}
          onSubmitDetails={login}
          onSubmitCode={handleCode}
          onRegister={() => setScreen("register")}
        />
      )}
      {screen === "register" && <Register onCancel={() => showLogin("")} onComplete={() => showLogin(REGISTERED)} />}
      {screen === "ballot" && ballot && (
        <Ballot
          ballot={ballot}
          ranking={ranking}
          onRankingChange={setRanking}
          onReview={() => setScreen("review")}
        />
      )}
      {screen === "review" && ballot && (
        <Review
          ballot={ballot}
          ranking={ranking}
          onBack={() => setScreen("ballot")}
          onSubmit={handleSubmit}
        />
      )}
      {screen === "receipt" && receipt && (
        // SR-15: finishing, by Done or by the countdown, resets the terminal
        <Receipt receipt={receipt} seconds={TERMINAL.receiptSeconds} onDone={ends.done} onTimeout={ends.receiptTimeout} />
      )}
      <SessionWarning
        open={shownWarning === "session"}
        secondsLeft={session.secondsLeft}
        minutes={SESSION_MINUTES}
        // SR-04: the warning offers more time only while the server still allows it
        canExtend={extension === "allowed"}
        onKeep={() => void handleKeepVoting()}
        onSignOut={ends.signOut}
      />
      {/* SR-15: an elector who has stopped using the screen is asked before the session ends */}
      <IdleWarning
        open={shownWarning === "idle"}
        secondsLeft={idle.warningSecondsLeft ?? 0}
        onStillHere={idle.stillHere}
      />
    </Layout>
  );
}
