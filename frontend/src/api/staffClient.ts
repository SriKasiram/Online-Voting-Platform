// SR-05, SR-06: the same fetch helper as the voter app (http.ts)
import { ApiError, request } from "./http";

// SR-06: the three calls the staff sign-in page makes. The same endpoints as the voter app
// (SR-01 password, then a TOTP code), so every SR-01 and SR-04 rule applies unchanged.
// Both clients share one request helper (http.ts).
// SR-05: the staff console's admin calls are below the sign-in calls.
function post<T>(path: string, body?: unknown): Promise<T | undefined> {
  return request<T | undefined>("POST", path, body);
}

// SR-06: step 1, the password
export async function staffLogin(username: string, password: string): Promise<void> {
  await post("/auth/login", { username, password });
}

// SR-06: step 2, the code. Returns the role, which only privileged accounts get back.
export async function staffVerify(code: string): Promise<string> {
  const result = await post<{ role?: string }>("/auth/verify", { otp_code: code });
  if (!result?.role) {
    // An elector account signed in here: end that session and fail like any other error
    await staffLogout().catch(() => undefined);
    throw new ApiError(403);
  }
  return result.role;
}

// SR-06: deletes the session on the server and clears the cookie
export async function staffLogout(): Promise<void> {
  await post("/auth/logout");
}

// ---------------------------------------------------------------
// SR-05: staff console: the four existing admin routes (backend/app/routers/admin.py), unchanged.
// The types are the routes' exact response shapes (backend/app/schemas.py).
// ---------------------------------------------------------------

export type StateCounts = { issued: number; voted: number };
export type DivisionTurnout = StateCounts & { division: string };
export type Turnout = { election: string; divisions: DivisionTurnout[]; total: StateCounts };
// SR-16: the fields GET /api/admin/audit-log returns, hashes as hex
export type AuditEntry = { id: number; created_at: string; actor: string; event_type: string; prev_hash: string; hash: string };
export type ChainCheck = { ok: true; entries: number } | { ok: false; first_bad_id: number };
export type ResetResult = { status: string };

/** SR-05: the most entries GET /api/admin/audit-log returns in one request (AUDIT_PAGE_MAX). */
export const AUDIT_LOG_MAX = 200;

// SR-05: an admin request. Every failure is an ApiError with the status and the server's reason code.
function admin<T>(method: "GET" | "POST", path: string): Promise<T> {
  return request<T>(method, `/admin${path}`);
}

// SR-05: polling officials and auditors (turnout:read)
export function getTurnout(): Promise<Turnout> {
  return admin<Turnout>("GET", "/turnout");
}

// SR-05: auditors (audit:read). The limit is kept between 1 and the server's maximum.
export function getAuditLog(limit: number): Promise<AuditEntry[]> {
  const size = Math.min(Math.max(1, Math.trunc(limit) || 1), AUDIT_LOG_MAX);
  return admin<AuditEntry[]>("GET", `/audit-log?limit=${size}`);
}

// SR-05: auditors (audit:verify): the server recomputes the SR-16 hash chain
export function verifyAuditChain(): Promise<ChainCheck> {
  return admin<ChainCheck>("GET", "/audit-log/verify");
}

// SR-05: polling officials (elector:reset). The roll ID is URL-encoded, so it can never change the path.
export function resetElector(rollId: string): Promise<ResetResult> {
  return admin<ResetResult>("POST", `/electors/${encodeURIComponent(rollId.trim())}/reset`);
}
