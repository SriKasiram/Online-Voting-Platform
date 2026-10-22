/**
 * SR-09: ballot selections are held only in React state, in this tab's memory. Nothing about the
 * ballot is written to browser storage, cookies, the URL or the history state, and
 * noBrowserStorage.test.ts fails the build if any source file starts to. Closing the tab
 * discards that memory, and everything here clears it sooner.
 */
import { ApiError } from "../api/client";
import type { BallotDefinition } from "../api/types";
import type { ReceiptDetails } from "../pages/Receipt";
import type { Ranking } from "./ballotRules";

// SR-09: App's ballot state: the ballot paper (with its one-time ballot token) and the ranking
export type BallotSetters = {
  setBallot: (ballot: BallotDefinition | null) => void;
  setRanking: (ranking: Ranking) => void;
};

// SR-09: the one place ballot state is cleared. Ballot and Review only render while a ballot is
// open, so their own state (undo history, announcements, the confirm tick, messages) goes with it.
export function clearBallotState({ setBallot, setRanking }: BallotSetters): void {
  setBallot(null);
  setRanking([]);
}

// SR-09: a 401 means the server no longer knows this session, so the ballot must go too
export function sessionLost(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401;
}

// SR-09: sign-out, the session timer and a lost session all end here: the selections go first,
// then the server is told. A failed logout changes nothing, as the server session also expires.
export async function endSession(clear: () => void, logout: () => Promise<void>): Promise<void> {
  clear();
  try {
    await logout();
  } catch {
    // The server session also expires on its own
  }
}

// SR-09: the server accepted the ballot. The selections go at once, and the receipt keeps only
// its reference, time, election and division: never the ranking.
export function acceptBallot(receiptId: string, ballot: BallotDefinition, setters: BallotSetters): ReceiptDetails {
  clearBallotState(setters);
  return {
    receiptId,
    acceptedAt: new Date(),
    electionName: ballot.electionName,
    divisionName: ballot.divisionName,
  };
}

// SR-09: the parts of window that registerPageLifecycle uses, so tests can pass a fake one
export type PageWindow = {
  addEventListener(type: "pagehide" | "pageshow", listener: (event: PageTransitionEvent) => void): void;
  removeEventListener(type: "pagehide" | "pageshow", listener: (event: PageTransitionEvent) => void): void;
  location: { reload(): void };
};

// SR-09: closing a tab discards its in-memory state on its own. These handlers exist for the
// back/forward cache, which can keep a whole page, memory included, and show it again later.
// pagehide clears the ballot as the page is left. pageshow from that cache reloads the app, so it
// starts again at sign-in. Returns a function that removes both listeners.
export function registerPageLifecycle(win: PageWindow, clear: () => void): () => void {
  const onHide = () => clear();
  const onShow = (event: PageTransitionEvent) => {
    if (event.persisted) win.location.reload();
  };
  win.addEventListener("pagehide", onHide);
  win.addEventListener("pageshow", onShow);
  return () => {
    win.removeEventListener("pagehide", onHide);
    win.removeEventListener("pageshow", onShow);
  };
}
