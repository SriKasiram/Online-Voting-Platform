// The shared fetch helper (http.ts); ApiError is re-exported so every existing import still works
import { ApiError, request } from "./http";
import type { BallotDefinition } from "./types";

export { ApiError };

/**
 * Every call the frontend makes to the FastAPI backend. Requests go to /api on
 * the same origin, which the dev server forwards to the backend (see
 * vite.config.ts). The routes live in backend/app/routers (auth.py and ballot.py).
 */
export const SESSION_MINUTES = Number(import.meta.env.VITE_SESSION_MINUTES) || 10;

type BallotResponse = {
  ballot_token: string;
  election_name: string;
  division_name: string;
  state_name: string;
  candidates: { id: number; given_name: string; surname: string; party: string }[];
};

/**
 * Sign in, part 1. The server answers the same way whether or not the username
 * and password are right, so this step never reveals which one was wrong.
 */
export async function login(username: string, password: string): Promise<void> {
  await request<void>("POST", "/auth/login", { username, password });
}

/** Sign in, part 2. Only this step tells the voter that sign in failed. */
export async function verifyCode(code: string): Promise<{ displayName: string }> {
  const result = await request<{ display_name: string }>("POST", "/auth/verify", {
    otp_code: code,
  });
  return { displayName: result.display_name };
}

/**
 * Starts a new full session. Sent only when the voter selects "Keep voting",
 * never on ordinary activity, so the server session and the on-screen timer
 * end at the same time.
 */
export async function extendSession(): Promise<void> {
  await request<void>("POST", "/auth/extend");
}

/** The ballot paper for the signed-in voter's division, with a one-time ballot token. */
export async function getBallot(): Promise<BallotDefinition> {
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
  const result = await request<{ receipt_id: string }>("POST", "/ballot/submit", {
    ballot_token: ballotToken,
    ranked_candidate_ids: ranking,
  });
  return { receiptId: result.receipt_id };
}

// SR-15: the terminal reset passes a signal, so a stalled server cannot keep the old session on screen
export async function logout(signal?: AbortSignal): Promise<void> {
  await request<void>("POST", "/auth/logout", undefined, signal);
}

export type RegistrationDetails = {
  givenName: string;
  surname: string;
  /** YYYY-MM-DD, as a date input gives it */
  dateOfBirth: string;
  postcode: string;
  enrolmentCode: string;
};

/** Registration, step 1. Any failure comes back the same way, as ApiError 400. */
export async function registerVerify(details: RegistrationDetails): Promise<void> {
  await request<void>("POST", "/register/verify", {
    given_name: details.givenName,
    surname: details.surname,
    date_of_birth: details.dateOfBirth,
    postcode: details.postcode,
    enrolment_code: details.enrolmentCode,
  });
}

/** Registration, step 2. Returns the authenticator secret, which the server shows only once. */
export async function registerAccount(
  username: string,
  password: string,
): Promise<{ otpauthUri: string; secret: string }> {
  const result = await request<{ otpauth_uri: string; secret: string }>("POST", "/register/account", {
    username,
    password,
  });
  return { otpauthUri: result.otpauth_uri, secret: result.secret };
}

/** Registration, step 3. Creates the account. The voter then signs in as usual. */
export async function registerConfirm(code: string): Promise<void> {
  await request<void>("POST", "/register/confirm", { otp_code: code });
}
