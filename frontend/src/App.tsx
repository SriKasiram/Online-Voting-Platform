import { useCallback, useState } from "react";
import {
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
import { useSessionTimer } from "./lib/useSessionTimer";
import Ballot from "./pages/Ballot";
import Login from "./pages/Login";
import Receipt, { type ReceiptDetails } from "./pages/Receipt";
import Review from "./pages/Review";

type Screen = "login" | "ballot" | "review" | "receipt";

const STEP: Record<Screen, number> = { login: 0, ballot: 1, review: 2, receipt: 3 };

/** The "Do you need more time?" box appears this many seconds before the session ends. */
const WARN_SECONDS = 60;

const SESSION_ENDED = "Your session ended, so you were signed out. Sign in again to vote.";

export default function App() {
  const [screen, setScreen] = useState<Screen>("login");
  const [voterName, setVoterName] = useState<string | null>(null);
  const [ballot, setBallot] = useState<BallotDefinition | null>(null);
  const [ranking, setRanking] = useState<Ranking>([]);
  const [receipt, setReceipt] = useState<ReceiptDetails | null>(null);
  const [notice, setNotice] = useState("");

  // Clears everything held in the browser, so the next voter on a shared
  // terminal starts from a blank screen.
  const signOut = useCallback(async (message = "") => {
    setScreen("login");
    setVoterName(null);
    setBallot(null);
    setRanking([]);
    setReceipt(null);
    setNotice(message);
    try {
      await logout();
    } catch {
      // The server session also expires on its own
    }
  }, []);

  const session = useSessionTimer(screen !== "login", SESSION_MINUTES, () => {
    void signOut(SESSION_ENDED);
  });

  const ballotOpen = screen === "ballot" || screen === "review";
  const warningOpen = ballotOpen && session.secondsLeft > 0 && session.secondsLeft <= WARN_SECONDS;

  async function handleKeepVoting() {
    session.extend();
    try {
      await extendSession();
    } catch {
      void signOut(SESSION_ENDED);
    }
  }

  async function handleCode(code: string) {
    const { displayName } = await verifyCode(code);
    const definition = await getBallot();
    setNotice("");
    setVoterName(displayName);
    setBallot(definition);
    setRanking([]);
    setScreen("ballot");
  }

  async function handleSubmit(ballotToken: string, ranked: number[]) {
    if (!ballot) throw new Error("No ballot is open");
    const { receiptId } = await submitBallot(ballotToken, ranked);
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
      {screen === "login" && <Login notice={notice} onSubmitDetails={login} onSubmitCode={handleCode} />}
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
        onKeep={() => void handleKeepVoting()}
        onSignOut={() => void signOut("You have signed out.")}
      />
    </Layout>
  );
}
