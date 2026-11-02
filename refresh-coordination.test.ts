/**
 * Cross-tab / cross-page refresh coordination (src/auth/refreshCoordinator.ts).
 *
 * Refresh tokens are single-use on the server. These tests pin the client
 * protocol that prevents a second tab or a reloaded page from presenting a
 * token whose rotation is still in flight.
 */
import { describe, expect, it, vi } from "vitest";

import {
  MAX_ROTATION_WAIT_MS,
  ROTATION_MARKER_KEY,
  coordinateRefresh,
  fingerprint,
  type CoordinatorEnv,
} from "@/auth/refreshCoordinator";

function makeEnv(overrides: Partial<CoordinatorEnv> = {}) {
  const store = new Map<string, string>();
  let clock = 1_000_000;
  let csrf: string | null = "csrf-A";
  const env: CoordinatorEnv & {
    store: Map<string, string>;
    setCsrf: (v: string | null) => void;
    advance: (ms: number) => void;
    sleeps: number[];
  } = {
    store,
    sleeps: [],
    storage: {
      getItem: (k) => store.get(k) ?? null,
      setItem: (k, v) => void store.set(k, v),
      removeItem: (k) => void store.delete(k),
    },
    readCsrf: () => csrf,
    now: () => clock,
    sleep: async (ms) => {
      env.sleeps.push(ms);
      clock += ms;
    },
    locks: null,
    setCsrf: (v) => {
      csrf = v;
    },
    advance: (ms) => {
      clock += ms;
    },
    ...overrides,
  };
  return env;
}

function plantMarker(env: ReturnType<typeof makeEnv>, csrf: string, ageMs = 0, id = "other") {
  env.store.set(
    ROTATION_MARKER_KEY,
    JSON.stringify({ id, fp: fingerprint(csrf), at: env.now() - ageMs }),
  );
}

describe("coordinateRefresh", () => {
  it("sends immediately when no rotation is in flight", async () => {
    const env = makeEnv();
    const send = vi.fn().mockResolvedValue("ok");
    await expect(coordinateRefresh(send, env)).resolves.toBe("ok");
    expect(send).toHaveBeenCalledTimes(1);
    expect(env.sleeps).toEqual([]);
  });

  it("marks the rotation while it is in flight and clears it afterwards", async () => {
    const env = makeEnv();
    let seen: string | undefined;
    await coordinateRefresh(async () => {
      seen = env.store.get(ROTATION_MARKER_KEY);
    }, env);
    expect(seen).toBeDefined();
    const marker = JSON.parse(seen!);
    expect(marker.fp).toBe(fingerprint("csrf-A"));
    expect(env.store.has(ROTATION_MARKER_KEY)).toBe(false);
  });

  it("never stores the raw CSRF token (or any token) in web storage", async () => {
    const env = makeEnv();
    env.setCsrf("super-secret-csrf-value");
    let seen = "";
    await coordinateRefresh(async () => {
      seen = env.store.get(ROTATION_MARKER_KEY) ?? "";
    }, env);
    expect(seen).not.toContain("super-secret-csrf-value");
  });

  it("clears the marker when the server answered with an HTTP error", async () => {
    const env = makeEnv();
    const httpError = Object.assign(new Error("503"), { status: 503 });
    await expect(coordinateRefresh(() => Promise.reject(httpError), env)).rejects.toThrow("503");
    expect(env.store.has(ROTATION_MARKER_KEY)).toBe(false);
  });

  it("keeps the marker when the request was aborted / never answered", async () => {
    // e.g. the page is being unloaded: the keepalive request may still
    // complete on the server, so the next page must wait for it.
    const env = makeEnv();
    const abort = new DOMException("The user aborted a request.", "AbortError");
    await expect(coordinateRefresh(() => Promise.reject(abort), env)).rejects.toBe(abort);
    expect(env.store.has(ROTATION_MARKER_KEY)).toBe(true);

    const network = new TypeError("Failed to fetch");
    const env2 = makeEnv();
    await expect(coordinateRefresh(() => Promise.reject(network), env2)).rejects.toBe(network);
    expect(env2.store.has(ROTATION_MARKER_KEY)).toBe(true);
  });

  it("waits for an interrupted rotation from a previous page to land", async () => {
    const env = makeEnv();
    plantMarker(env, "csrf-A", 200); // previous page was mid-rotation
    let presented: string | null = null;
    const send = vi.fn(async () => {
      presented = env.readCsrf();
    });
    // The keepalive response lands after ~300 ms: cookie rotates to csrf-B.
    const origSleep = env.sleep;
    env.sleep = async (ms) => {
      await origSleep(ms);
      if (env.sleeps.reduce((a, b) => a + b, 0) >= 300) env.setCsrf("csrf-B");
    };
    await coordinateRefresh(send, env);
    expect(presented).toBe("csrf-B"); // used the rotated token, not the consumed one
    expect(env.sleeps.reduce((a, b) => a + b, 0)).toBeLessThan(1000);
  });

  it("gives up waiting after the bounded timeout and then proceeds", async () => {
    const env = makeEnv();
    plantMarker(env, "csrf-A", 0);
    const send = vi.fn().mockResolvedValue("ok");
    await coordinateRefresh(send, env);
    const waited = env.sleeps.reduce((a, b) => a + b, 0);
    expect(waited).toBeGreaterThanOrEqual(MAX_ROTATION_WAIT_MS - 200);
    expect(waited).toBeLessThanOrEqual(MAX_ROTATION_WAIT_MS + 200);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("ignores and removes a stale marker", async () => {
    const env = makeEnv();
    plantMarker(env, "csrf-A", MAX_ROTATION_WAIT_MS + 1);
    await coordinateRefresh(vi.fn().mockResolvedValue("ok"), env);
    expect(env.sleeps).toEqual([]);
  });

  it("does not wait when the rotation already landed", async () => {
    const env = makeEnv();
    plantMarker(env, "csrf-OLD", 100); // cookie has since rotated to csrf-A
    await coordinateRefresh(vi.fn().mockResolvedValue("ok"), env);
    expect(env.sleeps).toEqual([]);
  });

  it("tolerates a corrupt marker", async () => {
    const env = makeEnv();
    env.store.set(ROTATION_MARKER_KEY, "{not json");
    await expect(coordinateRefresh(vi.fn().mockResolvedValue("ok"), env)).resolves.toBe("ok");
  });

  it("works without web storage (private mode / blocked storage)", async () => {
    const env = makeEnv({
      storage: {
        getItem: () => {
          throw new Error("blocked");
        },
        setItem: () => {
          throw new Error("blocked");
        },
        removeItem: () => {
          throw new Error("blocked");
        },
      },
    });
    await expect(coordinateRefresh(vi.fn().mockResolvedValue("ok"), env)).resolves.toBe("ok");
  });

  it("only clears its own marker", async () => {
    const env = makeEnv();
    await coordinateRefresh(async () => {
      plantMarker(env, "csrf-A", 0, "someone-else"); // another tab overwrote it
    }, env);
    expect(JSON.parse(env.store.get(ROTATION_MARKER_KEY)!).id).toBe("someone-else");
  });

  it("serialises refreshes across tabs through the Web Locks API", async () => {
    let chain = Promise.resolve();
    const lockNames: string[] = [];
    const locks = {
      request: <T>(name: string, cb: () => Promise<T>): Promise<T> => {
        lockNames.push(name);
        const run = chain.then(cb);
        chain = run.then(
          () => undefined,
          () => undefined,
        );
        return run;
      },
    };
    const env = makeEnv({ locks });
    const order: string[] = [];
    const slow = (tag: string) => async () => {
      order.push(`${tag}:start`);
      await Promise.resolve();
      await Promise.resolve();
      order.push(`${tag}:end`);
      return tag;
    };
    await Promise.all([coordinateRefresh(slow("a"), env), coordinateRefresh(slow("b"), env)]);
    expect(order).toEqual(["a:start", "a:end", "b:start", "b:end"]);
    expect(new Set(lockNames).size).toBe(1);
  });

  it("falls back to an uncoordinated refresh when Web Locks is unavailable", async () => {
    const env = makeEnv({ locks: null });
    await expect(coordinateRefresh(vi.fn().mockResolvedValue("ok"), env)).resolves.toBe("ok");
  });
});

describe("fingerprint", () => {
  it("is deterministic, short and does not contain the input", () => {
    expect(fingerprint("abc")).toBe(fingerprint("abc"));
    expect(fingerprint("abc")).not.toBe(fingerprint("abd"));
    expect(fingerprint("token-value-123")).toMatch(/^[0-9a-f]{8}$/);
  });
});
