import { MOCK_CANDIDATES, newMockBallot, randomCode } from "./mockData";
import type { BallotDefinition } from "./types";

/**
 * Mock mode (default) runs with built-in fake data and needs no backend.
 * Set VITE_USE_MOCK=false to call the FastAPI backend under /api instead.
 *
 * The real-mode request and response shapes below are a proposal for the
 * backend team to agree on. Change them here in one place if the API differs.
 */
export const USE_MOCK = import.meta.env.VITE_USE_MOCK !== "false";
export const SESSION_MINUTES = Number(import.meta.env.VITE_SESSION_MINUTES) || 10;

/**
 * Shown on the sign-in screen, before the voter's own ballot is loaded.
 * After sign in, every screen uses the division sent with the ballot.
 */
export const SIGN_IN_DIVISION = {
  electionName: "House of Representatives",
  divisionName: "Melbourne",
  stateName: "Victoria",
};

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number) {
    super(`Request failed with status ${status}`);
    this.status = status;
  }
}

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// ---------------------------------------------------------------
// Mock implementation
// ---------------------------------------------------------------
let mockToken: string | null = null;
let mockAwaitingCode = false;

async function mockLogin(username: string, password: string) {
  await wait(400);
  // Like the real server, this moves on to the code step without saying
  // whether the password was right
  if (!username.trim() || !password) throw new ApiError(400);
  mockAwaitingCode = true;
}

async function mockVerifyCode(code: string) {
  await wait(400);
  // 000000 always fails, so the demo can show the error message
  if (!mockAwaitingCode || !/^\d{6}$/.test(code) || code === "000000") {
    throw new ApiError(401);
  }
  mockAwaitingCode = false;
  return { displayName: "Demo voter" };
}

async function mockGetBallot(): Promise<BallotDefinition> {
  await wait(200);
  const ballot = newMockBallot();
  mockToken = ballot.ballotToken;
  return ballot;
}

async function mockSubmit(token: string, ranking: number[]) {
  await wait(500);
  const expected = MOCK_CANDIDATES.map((c) => c.id).sort((a, b) => a - b);
  const received = [...ranking].sort((a, b) => a - b);
  const valid =
    token === mockToken &&
    received.length === expected.length &&
    expected.every((id, i) => id === received[i]);
  if (!valid) throw new ApiError(400);
  mockToken = null; // a ballot token works once, so a replay is rejected
  return { receiptId: `${randomCode(4)}-${randomCode(4)}` };
}

// ---------------------------------------------------------------
// Real implementation (FastAPI backend)
// ---------------------------------------------------------------
function csrfToken(): string {
  // TODO: agree with the backend how the CSRF token is delivered. The usual
  // approach is a readable (not HttpOnly) csrf_token cookie echoed in a header.
  const match = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken(),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) throw new ApiError(response.status);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

type BallotResponse = {
  ballot_token: string;
  election_name: string;
  division_name: string;
  state_name: string;
  candidates: { id: number; given_name: string; surname: string; party: string }[];
};

// ---------------------------------------------------------------
// Public API used by the screens
// ---------------------------------------------------------------

/**
 * Sign in, part 1. The server should answer the same way whether or not the
 * password was right, and keep a short-lived "waiting for code" session.
 */
export async function login(username: string, password: string): Promise<void> {
  if (USE_MOCK) return mockLogin(username, password);
  await request<unknown>("POST", "/auth/login", { username, password });
}

/** Sign in, part 2. Only this step tells the voter that sign in failed. */
export async function verifyCode(code: string): Promise<{ displayName: string }> {
  if (USE_MOCK) return mockVerifyCode(code);
  const result = await request<{ display_name: string }>("POST", "/auth/verify", {
    otp_code: code,
  });
  return { displayName: result.display_name };
}

/**
 * Adds another full session length. Sent only when the voter selects
 * "Keep voting", never on ordinary activity, so the server session and the
 * on-screen timer end at the same time.
 */
export async function extendSession(): Promise<void> {
  if (USE_MOCK) return;
  await request<unknown>("POST", "/auth/extend");
}

export async function getBallot(): Promise<BallotDefinition> {
  if (USE_MOCK) return mockGetBallot();
  const result = await request<BallotResponse>("GET", "/ballot");
  return {
    ballotToken: result.ballot_token,
    electionName: result.election_name,
    divisionName: result.division_name,
    stateName: result.state_name,
    candidates: result.candidates.map((c) => ({
      id: c.id,
      givenName: c.given_name,
      surname: c.surname,
      party: c.party,
    })),
  };
}

/** `ranking` lists candidate ids from first preference to last. */
export async function submitBallot(
  ballotToken: string,
  ranking: number[],
): Promise<{ receiptId: string }> {
  if (USE_MOCK) return mockSubmit(ballotToken, ranking);
  const result = await request<{ receipt_id: string }>("POST", "/ballot/submit", {
    ballot_token: ballotToken,
    ranked_candidate_ids: ranking,
  });
  return { receiptId: result.receipt_id };
}

export async function logout(): Promise<void> {
  if (USE_MOCK) {
    mockToken = null;
    mockAwaitingCode = false;
    return;
  }
  await request<unknown>("POST", "/auth/logout");
}
