import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type { BallotDefinition } from "../api/types";
import type { Ranking } from "./ballotRules";
import {
  acceptBallot,
  clearBallotState,
  endSession,
  registerPageLifecycle,
  sessionLost,
  type BallotSetters,
  type PageWindow,
} from "./clientSession";

const ballot: BallotDefinition = {
  ballotToken: "one-time-ballot-token",
  electionName: "2027 federal election",
  divisionName: "Northgate",
  stateName: "Victoria",
  candidates: [
    { id: 10, givenName: "Hana", surname: "Ortega", party: "Harbour Party" },
    { id: 20, givenName: "Daniel", surname: "Whitfield", party: "Rural Alliance" },
    { id: 30, givenName: "Mei-Lin", surname: "Tran", party: "Green Horizon" },
  ],
};

// SR-09: stands in for App's React state, with a ballot open and every box numbered
function openBallot() {
  const state: { ballot: BallotDefinition | null; ranking: Ranking } = { ballot, ranking: [30, 10, 20] };
  const setters: BallotSetters = {
    setBallot: (next) => (state.ballot = next),
    setRanking: (next) => (state.ranking = next),
  };
  return { state, setters };
}

// SR-09: nothing from the ballot paper, its token or the ranking is left in `value`
function holdsNoBallot(value: unknown): boolean {
  const text = JSON.stringify(value);
  return !["one-time-ballot-token", "Ortega", "Whitfield", "Tran", "[30,10,20]"].some((part) => text.includes(part));
}

describe("SR-09: clearBallotState", () => {
  it("SR-09: resets the ballot paper, its ballot token and the ranking in one call", () => {
    const { state, setters } = openBallot();

    clearBallotState(setters);

    expect(state).toEqual({ ballot: null, ranking: [] });
    expect(holdsNoBallot(state)).toBe(true);
  });
});

describe("SR-09: when the ballot is cleared", () => {
  it("SR-09: a successful submission clears the selections, and the receipt holds none", () => {
    const { state, setters } = openBallot();

    const receipt = acceptBallot("RCPT-7Q4M", ballot, setters);

    expect(state).toEqual({ ballot: null, ranking: [] });
    expect(Object.keys(receipt).sort()).toEqual(["acceptedAt", "divisionName", "electionName", "receiptId"]);
    expect(receipt.receiptId).toBe("RCPT-7Q4M");
    expect(holdsNoBallot(receipt)).toBe(true);
  });

  it("SR-09: sign-out, the session timer and a lost session clear the selections before the server is told", async () => {
    const { state, setters } = openBallot();
    let ballotAtLogout: BallotDefinition | null | undefined;
    const logout = vi.fn(async () => {
      ballotAtLogout = state.ballot;
    });

    await endSession(() => clearBallotState(setters), logout);

    expect(logout).toHaveBeenCalledOnce();
    expect(ballotAtLogout).toBeNull();
    expect(state).toEqual({ ballot: null, ranking: [] });
  });

  it("SR-09: the selections are still cleared when the logout request fails", async () => {
    const { state, setters } = openBallot();

    await endSession(() => clearBallotState(setters), () => Promise.reject(new TypeError("Failed to fetch")));

    expect(state).toEqual({ ballot: null, ranking: [] });
  });

  it("SR-09: any 401 from the API is a lost session, and nothing else is", () => {
    expect(sessionLost(new ApiError(401, "not_signed_in"))).toBe(true);
    expect(sessionLost(new ApiError(401))).toBe(true);
    for (const other of [
      new ApiError(400, "invalid_ballot"),
      new ApiError(403, "forbidden"),
      new ApiError(409, "already_voted"),
      new ApiError(422, "informal_ballot"),
      new ApiError(503, "ballot_unavailable"),
      new TypeError("Failed to fetch"),
      undefined,
    ]) {
      expect(sessionLost(other)).toBe(false);
    }
  });
});

// SR-09: a window with only what registerPageLifecycle uses, and a way to fire its events
function fakeWindow() {
  const listeners = new Map<string, (event: PageTransitionEvent) => void>();
  const reload = vi.fn();
  const win: PageWindow = {
    addEventListener: (type, listener) => void listeners.set(type, listener),
    removeEventListener: (type, listener) => {
      if (listeners.get(type) === listener) listeners.delete(type);
    },
    location: { reload },
  };
  const fire = (type: string, persisted = false) => listeners.get(type)?.({ persisted } as PageTransitionEvent);
  return { win, listeners, reload, fire };
}

describe("SR-09: registerPageLifecycle", () => {
  it("SR-09: pagehide clears the ballot", () => {
    const { win, reload, fire } = fakeWindow();
    const clear = vi.fn();
    registerPageLifecycle(win, clear);

    fire("pagehide");

    expect(clear).toHaveBeenCalledOnce();
    expect(reload).not.toHaveBeenCalled();
  });

  it("SR-09: a page restored from the back/forward cache (persisted) reloads", () => {
    const { win, reload, fire } = fakeWindow();
    registerPageLifecycle(win, vi.fn());

    fire("pageshow", true);

    expect(reload).toHaveBeenCalledOnce();
  });

  it("SR-09: an ordinary page load (not persisted) does not reload", () => {
    const { win, reload, fire } = fakeWindow();
    registerPageLifecycle(win, vi.fn());

    fire("pageshow", false);

    expect(reload).not.toHaveBeenCalled();
  });

  it("SR-09: the returned cleanup removes both listeners", () => {
    const { win, listeners, reload, fire } = fakeWindow();
    const clear = vi.fn();
    const cleanup = registerPageLifecycle(win, clear);
    expect([...listeners.keys()].sort()).toEqual(["pagehide", "pageshow"]);

    cleanup();
    fire("pagehide");
    fire("pageshow", true);

    expect(listeners.size).toBe(0);
    expect(clear).not.toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
  });
});
