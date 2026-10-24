/**
 * The one fetch helper behind both API clients: the voter app (client.ts) and the staff page
 * (staffClient.ts, SR-05 and SR-06). Requests go to /api on the same origin and send the HttpOnly
 * session cookie; every failure is an ApiError with the status and the server's reason code.
 */

export class ApiError extends Error {
  readonly status: number;
  /** The server's short reason, such as "already_voted", when it sent one. */
  readonly code: string | undefined;
  constructor(status: number, code?: string) {
    super(`Request failed with status ${status}`);
    this.status = status;
    this.code = code;
  }
}

/** FastAPI errors look like {"detail": "already_voted"}. */
async function errorCode(response: Response): Promise<string | undefined> {
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "detail" in body && typeof body.detail === "string") {
      return body.detail;
    }
  } catch {
    // Not JSON
  }
  return undefined;
}

// SR-15: the terminal reset passes a signal, so a stalled server cannot keep the old session on screen
export async function request<T>(method: "GET" | "POST", path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method,
    // Sends the HttpOnly session cookie, which page scripts cannot read
    credentials: "same-origin",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });
  if (!response.ok) throw new ApiError(response.status, await errorCode(response));
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}
