import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError as ClientApiError } from "./client";
import { ApiError, request } from "./http";

function answer(status: number, body?: unknown) {
  const fetchMock = vi.fn(async () =>
    status === 204 ? new Response(null, { status }) : new Response(body === undefined ? "not json" : JSON.stringify(body), { status }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the shared fetch helper (http.ts)", () => {
  it("SR-05, SR-06: sends to /api with the session cookie, and JSON only when there is a body", async () => {
    const fetchMock = answer(200, { ok: true });

    expect(await request("POST", "/auth/login", { username: "a" })).toEqual({ ok: true });
    expect(fetchMock.mock.calls[0]).toEqual([
      "/api/auth/login",
      { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: '{"username":"a"}', signal: undefined },
    ]);

    await request("GET", "/admin/turnout");
    expect(fetchMock.mock.calls[1]).toEqual(["/api/admin/turnout", { method: "GET", credentials: "same-origin" }]);
  });

  it("SR-15: passes the abort signal through", async () => {
    const fetchMock = answer(204);
    const controller = new AbortController();

    expect(await request("POST", "/auth/logout", undefined, controller.signal)).toBeUndefined();
    expect((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].signal).toBe(controller.signal);
  });

  it("SR-05, SR-06: a failure is an ApiError with the status and the server's reason code", async () => {
    answer(409, { detail: "already_voted" });
    const error = await request("POST", "/ballot/submit", {}).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect([(error as ApiError).status, (error as ApiError).code]).toEqual([409, "already_voted"]);

    answer(502);
    const bare = await request("GET", "/ballot").catch((e: unknown) => e);
    expect([(bare as ApiError).status, (bare as ApiError).code]).toEqual([502, undefined]);
  });

  it("the voter client's ApiError is the same class, so instanceof checks keep working", () => {
    expect(ClientApiError).toBe(ApiError);
  });
});
