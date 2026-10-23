import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { SAFETY_MS, createTerminalReset, sessionEndHandlers, type AbortHandle, type ResetReason } from "./terminalReset";

// SR-15: a reset with every dependency recorded, and a logout whose behaviour each test chooses
function setUp(logout: (signal: AbortSignal) => Promise<unknown>, makeAbortController?: () => AbortHandle) {
  const calls: string[] = [];
  const navigatedAt: number[] = [];
  const started = Date.now();
  const reset = createTerminalReset({
    clear: () => calls.push("clear"),
    logout: (signal) => {
      calls.push("logout");
      return logout(signal);
    },
    navigate: () => {
      calls.push("navigate");
      navigatedAt.push(Date.now() - started);
    },
    logoutTimeoutMs: 3000,
    makeAbortController,
  });
  return { reset, calls, navigatedAt };
}

const never = () => new Promise<never>(() => {});

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("SR-15: resetTerminal", () => {
  it("SR-15: clears first, then logs out, then navigates", async () => {
    const { reset, calls } = setUp(async () => {});

    await reset("done");

    expect(calls).toEqual(["clear", "logout", "navigate"]);
  });

  it("SR-15: navigates as soon as a quick logout resolves, well within 5 seconds", async () => {
    const { reset, navigatedAt } = setUp(
      () => new Promise((resolve) => setTimeout(resolve, 200)),
    );

    const done = reset("sign_out");
    await vi.advanceTimersByTimeAsync(200);
    await done;

    expect(navigatedAt).toEqual([200]);
  });

  it("SR-15: still navigates when the logout request fails", async () => {
    const { reset, calls, navigatedAt } = setUp(() => Promise.reject(new TypeError("Failed to fetch")));

    await reset("unauthorised");

    expect(calls).toEqual(["clear", "logout", "navigate"]);
    expect(navigatedAt[0]).toBeLessThan(5000);
  });

  it("SR-15: a logout that never answers is aborted at 3 seconds, and the start page follows", async () => {
    let signal: AbortSignal | undefined;
    const { reset, navigatedAt } = setUp((s) => {
      signal = s;
      return never();
    });

    const done = reset("idle_timeout");
    await vi.advanceTimersByTimeAsync(2999);
    expect(navigatedAt).toEqual([]);
    expect(signal?.aborted).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    await done;

    expect(signal?.aborted).toBe(true);
    expect(navigatedAt).toEqual([3000]);
  });

  it("SR-15: the 4.5-second safety timer navigates even when logout and its abort both stall", async () => {
    const stalledAbort = (): AbortHandle => ({ signal: new AbortController().signal, abort: () => {} });
    const { reset, navigatedAt } = setUp(never, stalledAbort);

    void reset("receipt_timeout");
    await vi.advanceTimersByTimeAsync(SAFETY_MS - 1);
    expect(navigatedAt).toEqual([]);

    await vi.advanceTimersByTimeAsync(1);

    expect(SAFETY_MS).toBe(4500);
    expect(navigatedAt).toEqual([4500]);
  });

  it("SR-15: the reset still navigates when clearing throws", async () => {
    const navigate = vi.fn();
    const reset = createTerminalReset({
      clear: () => {
        throw new Error("render failed");
      },
      logout: async () => {},
      navigate,
      logoutTimeoutMs: 3000,
    });

    await reset("done");

    expect(navigate).toHaveBeenCalledOnce();
  });

  it("SR-15: only the first call runs; later ones do nothing", async () => {
    const { reset, calls } = setUp(async () => {});

    await Promise.all([reset("done"), reset("receipt_timeout"), reset("unauthorised")]);
    await reset("sign_out");
    await vi.advanceTimersByTimeAsync(10_000);

    expect(calls).toEqual(["clear", "logout", "navigate"]);
  });

  it("SR-15: navigates exactly once, even when the safety timer and the logout finish together", async () => {
    const stalledAbort = (): AbortHandle => ({ signal: new AbortController().signal, abort: () => {} });
    const { reset, calls } = setUp(() => new Promise((resolve) => setTimeout(resolve, SAFETY_MS)), stalledAbort);

    void reset("done");
    await vi.advanceTimersByTimeAsync(SAFETY_MS + 1000);

    expect(calls.filter((call) => call === "navigate")).toHaveLength(1);
  });
});

describe("SR-15: every session end goes through the reset", () => {
  function handlers() {
    const reasons: ResetReason[] = [];
    return { reasons, ends: sessionEndHandlers((reason) => reasons.push(reason)) };
  }

  it("SR-15: Done, the receipt countdown and the idle timeout", () => {
    const { reasons, ends } = handlers();

    ends.done();
    ends.receiptTimeout();
    ends.idleTimeout();

    expect(reasons).toEqual(["done", "receipt_timeout", "idle_timeout"]);
  });

  it("SR-15: the sign-out button and the SR-04 session expiry", () => {
    const { reasons, ends } = handlers();

    ends.signOut();
    ends.sessionExpired();

    expect(reasons).toEqual(["sign_out", "session_expired"]);
  });

  it("SR-15: any 401 from an elector call resets, and tells the caller to stop", () => {
    const { reasons, ends } = handlers();

    expect(ends.apiError(new ApiError(401, "not_signed_in"))).toBe(true);
    expect(ends.apiError(new ApiError(401))).toBe(true);

    expect(reasons).toEqual(["unauthorised", "unauthorised"]);
  });

  it("SR-15: other errors are left to the screen that made the call", () => {
    const { reasons, ends } = handlers();

    for (const other of [
      new ApiError(400, "invalid_ballot"),
      new ApiError(409, "already_voted"),
      new ApiError(503, "try_again"),
      new TypeError("Failed to fetch"),
    ]) {
      expect(ends.apiError(other)).toBe(false);
    }

    expect(reasons).toEqual([]);
  });
});
