/**
 * SR-15: the one way an elector's session ends on this device, whether they finish, walk away, sign
 * out or lose the session. The ballot goes first, then the server is told, then the start page is
 * loaded afresh, which discards everything in memory. That last step always happens within 4.5
 * seconds, even if the network or the server never answers, so a shared polling-place terminal is
 * back at the start screen within 5 seconds for the next elector.
 */
import { sessionLost } from "./clientSession";

// SR-15: only for readable code and tests. It is never logged, stored or sent, so it cannot be
// tied to an elector or a ballot.
export type ResetReason = "done" | "receipt_timeout" | "idle_timeout" | "sign_out" | "session_expired" | "unauthorised";

// SR-15: the start page must be back within 5 seconds; 4.5 leaves room for it to load
export const SAFETY_MS = 4500;

export type Timers = {
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
};

export const browserTimers: Timers = {
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export type AbortHandle = { signal: AbortSignal; abort(): void };

// SR-15: injected, so tests can run the reset without a browser
export type ResetDeps = {
  /** The SR-09 clearing: ballot, token, selections, receipt and the rest of the app's state. */
  clear: () => void;
  /** POST /api/auth/logout, given a signal that aborts it after logoutTimeoutMs. */
  logout: (signal: AbortSignal) => Promise<unknown>;
  /** A full navigation to the start page, replacing this history entry. */
  navigate: () => void;
  logoutTimeoutMs: number;
  timers?: Timers;
  makeAbortController?: () => AbortHandle;
};

// SR-15: settles when the signal aborts, so a logout that ignores its signal cannot hold the reset
function whenAborted(signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) resolve();
    else signal.addEventListener("abort", () => resolve(), { once: true });
  });
}

export function createTerminalReset(deps: ResetDeps): (reason: ResetReason) => Promise<void> {
  const timers = deps.timers ?? browserTimers;
  const makeAbortController = deps.makeAbortController ?? (() => new AbortController());
  let started = false;

  return async (_reason: ResetReason) => {
    // SR-15: Done, a timer and a 401 can arrive together; only the first one resets
    if (started) return;
    started = true;

    let navigated = false;
    const navigate = () => {
      if (navigated) return;
      navigated = true;
      deps.navigate();
    };
    // SR-15: armed before anything else, so nothing below can keep the old session on screen
    const safety = timers.setTimeout(navigate, SAFETY_MS);

    try {
      deps.clear();
    } catch {
      // SR-15: the navigation below discards the page's memory anyway
    }

    const controller = makeAbortController();
    const limit = timers.setTimeout(() => controller.abort(), deps.logoutTimeoutMs);
    try {
      await Promise.race([deps.logout(controller.signal), whenAborted(controller.signal)]);
    } catch {
      // SR-15: a failed or aborted logout must not stop the reset; the server session still
      // expires on its own (SR-04)
    } finally {
      timers.clearTimeout(limit);
    }
    timers.clearTimeout(safety);
    navigate();
  };
}

// SR-15: every way an elector's session ends, each sent to the same reset
export function sessionEndHandlers(reset: (reason: ResetReason) => void) {
  return {
    done: () => reset("done"),
    receiptTimeout: () => reset("receipt_timeout"),
    idleTimeout: () => reset("idle_timeout"),
    signOut: () => reset("sign_out"),
    sessionExpired: () => reset("session_expired"),
    /** True when the error was a 401 and the reset has started, so the caller stops there. */
    apiError: (error: unknown): boolean => {
      if (!sessionLost(error)) return false;
      reset("unauthorised");
      return true;
    },
  };
}
