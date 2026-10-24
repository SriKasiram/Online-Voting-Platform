import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "./client";
import { AUDIT_LOG_MAX, getAuditLog, getTurnout, resetElector, verifyAuditChain } from "./staffClient";

// SR-05: every console call against a recorded fetch, so URL, method and credentials are checked exactly
function answer(status: number, body?: unknown) {
  const fetchMock = vi.fn(async () =>
    body === undefined ? new Response("not json", { status }) : new Response(JSON.stringify(body), { status }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function lastCall(fetchMock: ReturnType<typeof answer>): [string, RequestInit] {
  return fetchMock.mock.calls.at(-1) as unknown as [string, RequestInit];
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("SR-05: staff console client", () => {
  it("SR-05: getTurnout is GET /api/admin/turnout with the session cookie", async () => {
    const turnout = { election: "E", divisions: [{ division: "Melbourne", issued: 1, voted: 1 }], total: { issued: 1, voted: 1 } };
    const fetchMock = answer(200, turnout);

    expect(await getTurnout()).toEqual(turnout);
    expect(lastCall(fetchMock)).toEqual(["/api/admin/turnout", { method: "GET", credentials: "same-origin" }]);
  });

  it("SR-05: getAuditLog asks for the limit, kept between 1 and the server maximum", async () => {
    const fetchMock = answer(200, []);

    await getAuditLog(50);
    expect(lastCall(fetchMock)).toEqual(["/api/admin/audit-log?limit=50", { method: "GET", credentials: "same-origin" }]);
    await getAuditLog(5000);
    expect(lastCall(fetchMock)[0]).toBe(`/api/admin/audit-log?limit=${AUDIT_LOG_MAX}`);
    await getAuditLog(0);
    expect(lastCall(fetchMock)[0]).toBe("/api/admin/audit-log?limit=1");
    expect(AUDIT_LOG_MAX).toBe(200);
  });

  it("SR-05: verifyAuditChain is GET /api/admin/audit-log/verify", async () => {
    const fetchMock = answer(200, { ok: true, entries: 3 });

    expect(await verifyAuditChain()).toEqual({ ok: true, entries: 3 });
    expect(lastCall(fetchMock)).toEqual(["/api/admin/audit-log/verify", { method: "GET", credentials: "same-origin" }]);
  });

  it("SR-05: resetElector is POST, with the roll ID URL-encoded so it cannot change the path", async () => {
    const fetchMock = answer(200, { status: "reset" });

    expect(await resetElector(" 4f6c0a52-0000-4000-8000-000000000000 ")).toEqual({ status: "reset" });
    expect(lastCall(fetchMock)).toEqual([
      "/api/admin/electors/4f6c0a52-0000-4000-8000-000000000000/reset",
      { method: "POST", credentials: "same-origin" },
    ]);
    await resetElector("../audit-log?x=1#y");
    expect(lastCall(fetchMock)[0]).toBe("/api/admin/electors/..%2Faudit-log%3Fx%3D1%23y/reset");
  });

  it("SR-05: 401, 403 and 409 become ApiError with the server's reason code", async () => {
    for (const [status, detail, call] of [
      [401, "not_signed_in", () => getTurnout()],
      [403, "forbidden", () => getAuditLog(20)],
      [409, "already_voted", () => resetElector("x")],
    ] as const) {
      answer(status, { detail });
      const error = await call().catch((e: unknown) => e);
      expect(error).toBeInstanceOf(ApiError);
      expect([(error as ApiError).status, (error as ApiError).code]).toEqual([status, detail]);
    }
  });

  it("SR-05: a server error without JSON is still an ApiError, and a network failure is passed on", async () => {
    answer(500);
    const error = await verifyAuditChain().catch((e: unknown) => e);
    expect([(error as ApiError).status, (error as ApiError).code]).toEqual([500, undefined]);

    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));
    await expect(getTurnout()).rejects.toBeInstanceOf(TypeError);
  });
});
