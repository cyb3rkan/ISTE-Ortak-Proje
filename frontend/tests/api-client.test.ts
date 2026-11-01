import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  NetworkError,
  enrichSingle,
  getHealth,
} from "@/lib/api";

/** Build a fake `Response`. */
function jsonResponse(
  body: unknown,
  status = 200,
  contentType = "application/json",
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": contentType },
  });
}

function textResponse(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html" },
  });
}

describe("api client", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("getHealth calls the /api/v1/health endpoint", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        status: "ok",
        service: "ioc-enricher",
        version: "2.0.0",
        providers_configured: 0,
        ai_enabled: false,
      }),
    );

    const result = await getHealth();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const calledUrl = String(fetchMock.mock.calls[0][0]);
    expect(calledUrl).toContain("/api/v1/health");
    expect(result.status).toBe("ok");
  });

  it("enrichSingle POSTs the correct payload", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        ioc: "8.8.8.8",
        ioc_type: "ipv4",
        risk: { score: 0, level: "LOW", reasons: [] },
        providers: [],
        mitre: [],
        meta: {},
      }),
    );

    await enrichSingle({ ioc: "8.8.8.8", ioc_type: "ipv4" });

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/api/v1/enrich");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({ ioc: "8.8.8.8", ioc_type: "ipv4" });
    expect(init.headers["Content-Type"]).toBe("application/json");
  });

  it("parses an RFC 7807 problem body into a typed ApiError on 422", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          type: "https://errors.ioc-enricher.local/request-validation",
          title: "Request validation failed",
          status: 422,
          detail: "One or more fields failed validation.",
          instance: "/api/v1/enrich",
          request_id: "req-xyz",
        },
        422,
        "application/problem+json",
      ),
    );

    await expect(
      enrichSingle({ ioc: "" }),
    ).rejects.toMatchObject({
      name: "ApiError",
      status: 422,
      requestId: "req-xyz",
    });
  });

  it("produces a generic ApiError when an error body is HTML/text", async () => {
    fetchMock.mockResolvedValueOnce(
      textResponse("<html><body>502 Bad Gateway</body></html>", 502),
    );

    let caught: unknown;
    try {
      await getHealth();
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(ApiError);
    const apiErr = caught as ApiError;
    expect(apiErr.status).toBe(502);
    // The raw HTML body must NOT leak into the error message.
    expect(apiErr.message).not.toContain("<html>");
    expect(apiErr.problem).toBeNull();
  });

  it("raises a NetworkError when fetch aborts (timeout path)", async () => {
    // The client wraps every request in an AbortController-driven timeout.
    // Rather than waiting the real 30s, we pass an already-aborting caller
    // signal: the client links it to its internal controller, fetch sees an
    // aborted signal and rejects with an AbortError — the exact shape the
    // browser produces when the timeout elapses.
    fetchMock.mockImplementationOnce(
      (_url: string, init: RequestInit) =>
        new Promise((_resolve, reject) => {
          const signal = init.signal;
          if (signal?.aborted) {
            reject(new DOMException("aborted", "AbortError"));
            return;
          }
          signal?.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          });
        }),
    );

    const caller = new AbortController();
    const promise = getHealth(caller.signal);
    caller.abort();

    await expect(promise).rejects.toBeInstanceOf(NetworkError);
  });
});
