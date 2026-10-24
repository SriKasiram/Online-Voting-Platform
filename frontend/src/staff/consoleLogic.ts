import { ApiError } from "../api/client";
import type { AuditEntry, ChainCheck, Turnout } from "../api/staffClient";

// SR-05: staff console logic, kept free of React so every rule can be tested on its own

export type TabId = "turnout" | "reset" | "audit" | "verify";
export type Tab = { id: TabId; label: string };

const TURNOUT: Tab = { id: "turnout", label: "Turnout" };
const RESET: Tab = { id: "reset", label: "Reset elector" };
const AUDIT: Tab = { id: "audit", label: "Audit log" };
const VERIFY: Tab = { id: "verify", label: "Verify chain" };

/**
 * SR-05: the tabs a role sees. Display only: the server decides access on every request
 * (backend/app/rbac.py), so a hidden tab is a convenience, never a control, and a direct call to a
 * route outside the role still gets 403. Electors and unknown roles get no tabs at all.
 */
export function tabsForRole(role: string): Tab[] {
  switch (role) {
    case "polling_official":
      return [TURNOUT, RESET];
    case "auditor":
      return [TURNOUT, AUDIT, VERIFY];
    default:
      return [];
  }
}

/** SR-05: arrow keys move between tabs (wrapping), Home and End go to the ends. Null for any other key. */
export function nextTabIndex(current: number, key: string, count: number): number | null {
  if (count === 0) return null;
  switch (key) {
    case "ArrowRight":
    case "ArrowDown":
      return (current + 1) % count;
    case "ArrowLeft":
    case "ArrowUp":
      return (current - 1 + count) % count;
    case "Home":
      return 0;
    case "End":
      return count - 1;
    default:
      return null;
  }
}

// SR-06: the same words the staff page already uses when a session ends
export const SESSION_ENDED = "Your session has ended. Sign in again.";
export const FORBIDDEN = "You do not have access to this function.";
export const RESET_DONE = "Elector reset";
export const RESET_ALREADY_VOTED = "This elector has already voted and cannot be reset";
export const RESET_FAILED = "Reset failed";

/** SR-05: the audit log sizes on offer; the server never returns more than 200 (AUDIT_PAGE_MAX). */
export const AUDIT_LIMITS = [20, 50, 100] as const;

export type FailureKind = "session_ended" | "forbidden" | "failed";

/** SR-05, SR-06: 401 means the session is gone, 403 that the role may not do this; anything else just failed. */
export function failureKind(error: unknown): FailureKind {
  if (error instanceof ApiError && error.status === 401) return "session_ended";
  if (error instanceof ApiError && error.status === 403) return "forbidden";
  return "failed";
}

/** SR-05: the reset outcome, from no error (success) or the error the request threw. */
export function resetMessage(error: unknown): string {
  if (error === null) return RESET_DONE;
  if (error instanceof ApiError && error.status === 409) return RESET_ALREADY_VOTED;
  if (failureKind(error) === "forbidden") return FORBIDDEN;
  return RESET_FAILED;
}

/** SR-05: Reset is enabled only with a roll ID, the confirmation ticked, and no request running. */
export function canReset(rollId: string, confirmed: boolean, busy: boolean): boolean {
  return confirmed && rollId.trim() !== "" && !busy;
}

// ---------------------------------------------------------------
// Console state: one reducer, so "clear" empties every tab at once
// ---------------------------------------------------------------

export type ConsoleState = {
  busy: boolean;
  turnout: { data: Turnout; loadedAt: Date } | null;
  audit: AuditEntry[] | null;
  auditLimit: number;
  chain: ChainCheck | null;
  /** The text of each tab's aria-live region. */
  messages: Record<TabId, string>;
};

export const INITIAL_CONSOLE: ConsoleState = {
  busy: false,
  turnout: null,
  audit: null,
  auditLimit: AUDIT_LIMITS[0],
  chain: null,
  messages: { turnout: "", reset: "", audit: "", verify: "" },
};

export type ConsoleAction =
  | { type: "start"; tab: TabId }
  | { type: "turnout"; data: Turnout; at: Date }
  | { type: "audit"; entries: AuditEntry[] }
  | { type: "limit"; limit: number }
  | { type: "chain"; result: ChainCheck }
  | { type: "message"; tab: TabId; message: string }
  | { type: "clear" };

export function consoleReducer(state: ConsoleState, action: ConsoleAction): ConsoleState {
  const say = (tab: TabId, message: string) => ({ ...state.messages, [tab]: message });
  switch (action.type) {
    case "start":
      return { ...state, busy: true, messages: say(action.tab, "Loading") };
    case "turnout":
      return { ...state, busy: false, turnout: { data: action.data, loadedAt: action.at }, messages: say("turnout", "Turnout updated") };
    case "audit":
      return { ...state, busy: false, audit: action.entries, messages: say("audit", `${action.entries.length} audit entries loaded`) };
    case "limit":
      return { ...state, auditLimit: action.limit };
    case "chain":
      return { ...state, busy: false, chain: action.result, messages: say("verify", chainSummary(action.result)) };
    case "message":
      return { ...state, busy: false, messages: say(action.tab, action.message) };
    case "clear":
      // SR-06: a 401 or the end of the 10-minute session leaves nothing from the console behind
      return INITIAL_CONSOLE;
  }
}

/** SR-05: the verify result as text, so PASS or FAIL never depends on colour alone. */
export function chainSummary(result: ChainCheck): string {
  return result.ok
    ? `PASS: ${result.entries} audit entries checked, the chain is intact`
    : `FAIL: the chain breaks at audit entry ${result.first_bad_id}`;
}

/**
 * SR-05, SR-06: runs one console request. A result goes to onResult. A 401 clears the console
 * and ends the session with the usual message; a 403 or any other failure becomes the tab's message.
 */
export async function runRequest<T>(options: {
  tab: TabId;
  call: () => Promise<T>;
  onResult: (result: T) => void;
  failed: (error: unknown) => string;
  dispatch: (action: ConsoleAction) => void;
  onSessionEnded: (message: string) => void;
}): Promise<void> {
  const { tab, call, onResult, failed, dispatch, onSessionEnded } = options;
  dispatch({ type: "start", tab });
  let result: T;
  try {
    result = await call();
  } catch (error) {
    if (failureKind(error) === "session_ended") {
      dispatch({ type: "clear" });
      onSessionEnded(SESSION_ENDED);
      return;
    }
    dispatch({ type: "message", tab, message: failureKind(error) === "forbidden" ? FORBIDDEN : failed(error) });
    return;
  }
  onResult(result);
}
