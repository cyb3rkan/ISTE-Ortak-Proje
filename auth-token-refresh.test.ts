/**
 * Tests for the in-memory token store and the API client's
 * 401 -> refresh -> retry behaviour.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Force jwt mode so the api client's refresh path is active.
vi.mock("@/lib/config", async () => {
  const actual =
    await vi.importActual<typeof import("@/lib/config")>("@/lib/config");
  return {
    ...actual,
    config: { ...actual.config, authMode: "jwt" },
  };
});

import {
  clearAccessToken,
  getAccessToken,
  setAccessToken,
  setSessionLostHandler,
} from "@/auth/tokenStore";
import { enrichSingle } from "@/lib/api";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const ENRICH_OK = {
  ioc: "8.8.8.8",
  ioc_type: "ipv4",
  risk: { score: 0, level: "LOW", reasons: [] },
  providers: [],
  mitre: [],
  meta: {},
};

const REFRESH_OK = {
  access_token: "fresh-token-xyz",
  token_type: "bearer",
  expires_in: 900,
  user: { username: "admin", role: "admin" },
};

describe("token store + api client refresh", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    clearAccessToken();
    setSessionLostHandler(null);
    document.cookie = "";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    clearAccessToken();
  });

  it("attaches the in-memory access token as a Bearer header", async () => {
    setAccessToken("token-in-memory");
    fetchMock.mockResolvedValueOnce(jsonResponse(ENRICH_OK));

    await enrichSingle({ ioc: "8.8.8.8" });

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer token-in-memory");
    // The browser must NEVER send an API key header.
    expect(headers["X-API-Key"]).toBeUndefined();
  });

  it("refreshes once and retries the request on a 401", async () => {
    setAccessToken("stale-token");
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ detail: "expired" }, 401)) // enrich
      .mockResolvedValueOnce(jsonResponse(REFRESH_OK, 200)) // /auth/refresh
      .mockResolvedValueOnce(jsonResponse(ENRICH_OK, 200)); // retry

    const result = await enrichSingle({ ioc: "8.8.8.8" });

    expect(result.ioc).toBe("8.8.8.8");
    expect(fetchMock).toHaveBeenCalledTimes(3);
    // The refresh call hits /auth/refresh.
    expect(String(fetchMock.mock.calls[1][0])).toContain("/auth/refresh");
    // The retry carries the freshly minted token.
    const retryHeaders = (fetchMock.mock.calls[2][1] as RequestInit)
      .headers as Record<string, string>;
    expect(retryHeaders.Authorization).toBe("Bearer fresh-token-xyz");
    expect(getAccessToken()).toBe("fresh-token-xyz");
  });

  it("drops to anonymous (session-lost handler) when refresh fails", async () => {
    setAccessToken("stale-token");
    const sessionLost = vi.fn();
    setSessionLostHandler(sessionLost);

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ detail: "expired" }, 401)) // enrich
      .mockResolvedValueOnce(jsonResponse({ detail: "no cookie" }, 401)); // refresh fails

    await expect(enrichSingle({ ioc: "8.8.8.8" })).rejects.toMatchObject({
      status: 401,
    });
    expect(sessionLost).toHaveBeenCalledTimes(1);
    expect(getAccessToken()).toBeNull();
  });

  it("does not retry more than once", async () => {
    setAccessToken("stale-token");
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ detail: "expired" }, 401)) // enrich
      .mockResolvedValueOnce(jsonResponse(REFRESH_OK, 200)) // refresh ok
      .mockResolvedValueOnce(jsonResponse({ detail: "still 401" }, 401)); // retry 401

    await expect(enrichSingle({ ioc: "8.8.8.8" })).rejects.toMatchObject({
      status: 401,
    });
    // enrich + refresh + one retry == 3; no further attempts.
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});

describe("refresh request survives page unload and is coordinated", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    clearAccessToken();
    setSessionLostHandler(null);
    localStorage.clear();
    document.cookie = "ioc_csrf_token=csrf-123; path=/";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.cookie = "ioc_csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  });

  it("sends the refresh with keepalive, credentials and the CSRF header", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(REFRESH_OK));
    const { tryRefreshAccessToken } = await import("@/auth/tokenStore");
    await expect(tryRefreshAccessToken()).resolves.toBe("fresh-token-xyz");
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/auth/refresh");
    expect(init.keepalive).toBe(true);
    expect(init.credentials).toBe("include");
    expect(init.headers["X-CSRF-Token"]).toBe("csrf-123");
  });

  it("marks the rotation in flight only while the request is pending", async () => {
    let markerDuringRequest: string | null = null;
    fetchMock.mockImplementationOnce(async () => {
      markerDuringRequest = localStorage.getItem("ioc-enricher:rotation-in-flight");
      return jsonResponse(REFRESH_OK);
    });
    const { tryRefreshAccessToken } = await import("@/auth/tokenStore");
    await tryRefreshAccessToken();
    expect(markerDuringRequest).not.toBeNull();
    expect(markerDuringRequest).not.toContain("csrf-123");
    expect(localStorage.getItem("ioc-enricher:rotation-in-flight")).toBeNull();
  });
});

describe("a stale refresh failure never undoes a newer login", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    clearAccessToken();
    localStorage.clear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    setSessionLostHandler(null);
  });

  it("keeps the token set by a login that completed while the refresh was pending", async () => {
    let answerRefresh: (r: Response) => void = () => {};
    fetchMock.mockImplementationOnce(
      () => new Promise<Response>((resolve) => (answerRefresh = resolve)),
    );
    const sessionLost = vi.fn();
    setSessionLostHandler(sessionLost);
    const { tryRefreshAccessToken } = await import("@/auth/tokenStore");

    const pending = tryRefreshAccessToken(); // silent refresh on page load
    await Promise.resolve();
    setAccessToken("token-from-login"); // user logs in meanwhile
    answerRefresh(jsonResponse({ detail: "no refresh token" }, 401)); // late failure

    await expect(pending).resolves.toBe("token-from-login");
    expect(getAccessToken()).toBe("token-from-login");
    expect(sessionLost).not.toHaveBeenCalled();
  });

  it("still signs out when nothing newer happened", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail: "expired" }, 401));
    const sessionLost = vi.fn();
    setSessionLostHandler(sessionLost);
    setAccessToken("old-token");
    const { tryRefreshAccessToken } = await import("@/auth/tokenStore");
    await expect(tryRefreshAccessToken()).resolves.toBeNull();
    expect(getAccessToken()).toBeNull();
    expect(sessionLost).toHaveBeenCalledTimes(1);
  });
});
