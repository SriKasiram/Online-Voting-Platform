import { ApiError } from "./client";

// SR-06: the three calls the staff sign-in page makes. The same endpoints as the voter app
// (SR-01 password, then a TOTP code), so every SR-01 and SR-04 rule applies unchanged.
// Never calls an admin route. client.ts keeps its request helper private, so this is its own.
async function post<T>(path: string, body?: unknown): Promise<T | undefined> {
  const response = await fetch(`/api${path}`, {
    method: "POST",
    // Sends the HttpOnly session cookie, which page scripts cannot read
    credentials: "same-origin",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) throw new ApiError(response.status);
  return response.status === 204 ? undefined : ((await response.json()) as T);
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
