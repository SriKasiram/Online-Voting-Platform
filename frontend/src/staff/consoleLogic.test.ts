import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import {
  FORBIDDEN,
  INITIAL_CONSOLE,
  RESET_ALREADY_VOTED,
  RESET_DONE,
  RESET_FAILED,
  SESSION_ENDED,
  canReset,
  chainSummary,
  consoleReducer,
  failureKind,
  nextTabIndex,
  resetMessage,
  runRequest,
  tabsForRole,
  type ConsoleAction,
  type ConsoleState,
} from "./consoleLogic";

const TURNOUT = { election: "Test election", divisions: [{ division: "Melbourne", issued: 1, voted: 1 }], total: { issued: 1, voted: 1 } };

describe("SR-05: tabsForRole", () => {
  it("SR-05: a polling official sees Turnout and Reset elector", () => {
    expect(tabsForRole("polling_official").map((tab) => tab.label)).toEqual(["Turnout", "Reset elector"]);
  });

  it("SR-05: an auditor sees Turnout, Audit log and Verify chain", () => {
    expect(tabsForRole("auditor").map((tab) => tab.label)).toEqual(["Turnout", "Audit log", "Verify chain"]);
  });

  it("SR-05: an elector or an unknown role sees no tabs", () => {
    for (const role of ["elector", "", "admin", "AUDITOR", "polling official"]) {
      expect(tabsForRole(role)).toEqual([]);
    }
  });
});

describe("SR-05: tab keyboard movement", () => {
  it("SR-05: arrow keys wrap, Home and End go to the ends, other keys do nothing", () => {
    expect(nextTabIndex(0, "ArrowRight", 3)).toBe(1);
    expect(nextTabIndex(2, "ArrowRight", 3)).toBe(0);
    expect(nextTabIndex(0, "ArrowLeft", 3)).toBe(2);
    expect(nextTabIndex(1, "ArrowDown", 2)).toBe(0);
    expect(nextTabIndex(0, "ArrowUp", 2)).toBe(1);
    expect(nextTabIndex(1, "Home", 3)).toBe(0);
    expect(nextTabIndex(0, "End", 3)).toBe(2);
    expect(nextTabIndex(0, "Enter", 3)).toBeNull();
    expect(nextTabIndex(0, "ArrowRight", 0)).toBeNull();
  });
});

describe("SR-05: errors", () => {
  it("SR-05, SR-06: 401 ends the session, 403 is no access, anything else failed", () => {
    expect(failureKind(new ApiError(401, "not_signed_in"))).toBe("session_ended");
    expect(failureKind(new ApiError(403, "forbidden"))).toBe("forbidden");
    expect(failureKind(new ApiError(500))).toBe("failed");
    expect(failureKind(new TypeError("Failed to fetch"))).toBe("failed");
  });
});

describe("SR-05: reset elector", () => {
  it("SR-05: Reset stays disabled until a roll ID is given and the confirmation is ticked", () => {
    expect(canReset("", false, false)).toBe(false);
    expect(canReset("4f6c0a52-0000-4000-8000-000000000000", false, false)).toBe(false);
    expect(canReset("   ", true, false)).toBe(false);
    expect(canReset("4f6c0a52-0000-4000-8000-000000000000", true, false)).toBe(true);
  });

  it("SR-05: Reset stays disabled while a request runs", () => {
    expect(canReset("4f6c0a52-0000-4000-8000-000000000000", true, true)).toBe(false);
  });

  it("SR-05: the reset messages: reset, already voted, no access, or failed", () => {
    expect(resetMessage(null)).toBe(RESET_DONE);
    expect(resetMessage(new ApiError(409, "already_voted"))).toBe(RESET_ALREADY_VOTED);
    expect(resetMessage(new ApiError(403, "forbidden"))).toBe(FORBIDDEN);
    for (const error of [new ApiError(404, "not_found"), new ApiError(422), new ApiError(500), new TypeError("Failed to fetch")]) {
      expect(resetMessage(error)).toBe(RESET_FAILED);
    }
    expect([RESET_DONE, RESET_ALREADY_VOTED, RESET_FAILED]).toEqual([
      "Elector reset",
      "This elector has already voted and cannot be reset",
      "Reset failed",
    ]);
  });
});

describe("SR-05: verify chain", () => {
  it("SR-05: PASS or FAIL is in the text, never shown by colour alone", () => {
    expect(chainSummary({ ok: true, entries: 42 })).toMatch(/^PASS: 42 audit entries checked/);
    expect(chainSummary({ ok: false, first_bad_id: 7 })).toMatch(/^FAIL: .* 7$/);
  });
});

function loaded(): ConsoleState {
  let state = INITIAL_CONSOLE;
  const steps: ConsoleAction[] = [
    { type: "turnout", data: TURNOUT, at: new Date() },
    { type: "audit", entries: [{ id: 1, created_at: "2026-10-24T00:00:00Z", actor: "script", event_type: "STAFF_CREATED", prev_hash: "00", hash: "ab" }] },
    { type: "limit", limit: 100 },
    { type: "chain", result: { ok: true, entries: 1 } },
    { type: "message", tab: "reset", message: RESET_DONE },
  ];
  for (const step of steps) state = consoleReducer(state, step);
  return state;
}

describe("SR-05, SR-06: console state", () => {
  it("SR-05: a request marks the console busy, and its result clears that", () => {
    const busy = consoleReducer(INITIAL_CONSOLE, { type: "start", tab: "turnout" });
    expect(busy.busy).toBe(true);
    expect(consoleReducer(busy, { type: "turnout", data: TURNOUT, at: new Date() }).busy).toBe(false);
    expect(consoleReducer(busy, { type: "message", tab: "turnout", message: FORBIDDEN }).busy).toBe(false);
  });

  it("SR-06: clear empties every tab at once", () => {
    const state = loaded();
    expect(state.turnout).not.toBeNull();
    expect(state.audit).not.toBeNull();

    expect(consoleReducer(state, { type: "clear" })).toEqual(INITIAL_CONSOLE);
  });

  it("SR-06: a 401 clears the console and returns to sign-in with the session-ended message", async () => {
    let state = loaded();
    const dispatch = (action: ConsoleAction) => {
      state = consoleReducer(state, action);
    };
    const onSessionEnded = vi.fn();
    const onResult = vi.fn();

    await runRequest({
      tab: "audit",
      call: () => Promise.reject(new ApiError(401, "not_signed_in")),
      onResult,
      failed: () => "should not be used",
      dispatch,
      onSessionEnded,
    });

    expect(state).toEqual(INITIAL_CONSOLE);
    expect(onSessionEnded).toHaveBeenCalledWith(SESSION_ENDED);
    expect(SESSION_ENDED).toBe("Your session has ended. Sign in again.");
    expect(onResult).not.toHaveBeenCalled();
  });

  it("SR-05: a 403 shows the no-access message and keeps the session", async () => {
    let state = INITIAL_CONSOLE;
    const onSessionEnded = vi.fn();

    await runRequest({
      tab: "verify",
      call: () => Promise.reject(new ApiError(403, "forbidden")),
      onResult: vi.fn(),
      failed: () => "should not be used",
      dispatch: (action) => {
        state = consoleReducer(state, action);
      },
      onSessionEnded,
    });

    expect(state.messages.verify).toBe("You do not have access to this function.");
    expect(state.busy).toBe(false);
    expect(onSessionEnded).not.toHaveBeenCalled();
  });

  it("SR-05: any other failure shows the tab's own message", async () => {
    let state = INITIAL_CONSOLE;

    await runRequest({
      tab: "turnout",
      call: () => Promise.reject(new TypeError("Failed to fetch")),
      onResult: vi.fn(),
      failed: () => "Turnout could not be loaded. Try again.",
      dispatch: (action) => {
        state = consoleReducer(state, action);
      },
      onSessionEnded: vi.fn(),
    });

    expect(state.messages.turnout).toBe("Turnout could not be loaded. Try again.");
  });

  it("SR-05: a result goes to onResult", async () => {
    const onResult = vi.fn();

    await runRequest({ tab: "turnout", call: async () => TURNOUT, onResult, failed: () => "", dispatch: vi.fn(), onSessionEnded: vi.fn() });

    expect(onResult).toHaveBeenCalledWith(TURNOUT);
  });
});
