import { useCallback, useState } from "react";
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
import Layout from "./components/Layout";
import SessionWarning from "./components/SessionWarning";
import type { Ranking } from "./lib/ballotRules";
import { useSessionTimer } from "./lib/hooks";
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

  // Clears everything held in the browser, so the next voter on a shared
  // terminal starts from a blank screen.
  const signOut = useCallback(async (message = "") => {
    setScreen("login");
    setVoterName(null);
    setBallot(null);
    setRanking([]);
    setReceipt(null);
    setNotice(message);
    setLoginKey((key) => key + 1);
    setExtension("allowed"); // SR-04: the next sign in starts with its extensions unused
    try {
      await logout();
    } catch {
      // The server session also expires on its own
    }
  }, []);

  // Runs only while someone is signed in. Registration has its own 10-minute limit on the server.
  const signedIn = screen === "ballot" || screen === "review" || screen === "receipt";
  const session = useSessionTimer(signedIn, SESSION_MINUTES, () => {
    void signOut(SESSION_ENDED);
  });

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
      void signOut(SESSION_ENDED);
    }
  }

  async function handleCode(code: string) {
    // A wrong code throws here, and the sign-in form shows its usual message
    const { displayName } = await verifyCode(code);
    let definition: BallotDefinition;
    try {
      definition = await getBallot();
    } catch (error) {
      // Signed in, but this account gets no ballot. End the session and say why.
      void signOut(noBallotMessage(error));
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
      if (error instanceof ApiError && error.status === 401) {
        void signOut(SESSION_ENDED);
        return;
      }
      if (error instanceof ApiError && error.code === "already_voted") {
        void signOut(noBallotMessage(error));
        return;
      }
      // Anything else: the review screen offers to try again
      throw error;
    }
    setReceipt({
      receiptId,
      acceptedAt: new Date(),
      electionName: ballot.electionName,
      divisionName: ballot.divisionName,
    });
    // Selections are dropped as soon as the ballot is accepted
    setBallot(null);
    setRanking([]);
    setScreen("receipt");
  }

  return (
    <Layout
      step={STEP[screen]}
      voterName={voterName}
      sessionSecondsLeft={ballotOpen ? session.secondsLeft : null}
      onSignOut={() => void signOut("You have signed out.")}
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
        <Receipt
          receipt={receipt}
          onFinish={() => void signOut("You have been signed out. Thank you for voting.")}
        />
      )}
      <SessionWarning
        open={warningOpen}
        secondsLeft={session.secondsLeft}
        minutes={SESSION_MINUTES}
        // SR-04: the warning offers more time only while the server still allows it
        canExtend={extension === "allowed"}
        onKeep={() => void handleKeepVoting()}
        onSignOut={() => void signOut("You have signed out.")}
      />
    </Layout>
  );
}
