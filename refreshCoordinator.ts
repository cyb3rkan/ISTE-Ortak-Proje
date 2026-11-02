/**
 * Cross-tab / cross-page coordination for refresh-token rotation.
 *
 * WHY: refresh tokens are strictly single-use on the server. Two situations
 * used to present an already-consumed token and log the user out:
 *
 *  1. Several tabs refreshing at the same moment (same cookie jar).
 *  2. A reload / navigation that unloads the page while its refresh is in
 *     flight: the server had already rotated the token, but the browser
 *     dropped the response, so the new cookie never arrived.
 *
 * HOW (no server-side relaxation, no token in web storage):
 *  - The refresh request itself uses `keepalive` (see authApi.refreshRequest)
 *    so an interrupted rotation still completes and its Set-Cookie is applied.
 *  - Refreshes are serialised across tabs with the Web Locks API; each tab
 *    therefore presents the token left by the previous rotation.
 *  - Before sending, a page records an "in flight" marker in localStorage:
 *    a random id, a timestamp and a non-reversible FINGERPRINT of the current
 *    CSRF cookie (the CSRF cookie rotates together with the refresh token).
 *    A page that finds a fresh marker whose fingerprint still matches the
 *    current CSRF cookie knows a rotation started by an unloaded page has not
 *    landed yet, and waits (bounded) for the cookie to change.
 *
 * The marker holds no credential. Without Web Locks (non-secure contexts) or
 * without localStorage, the code degrades to the previous behaviour.
 */
import { readCsrfToken } from "./authApi";

export const REFRESH_LOCK_NAME = "ioc-enricher:auth-refresh";
export const ROTATION_MARKER_KEY = "ioc-enricher:rotation-in-flight";
/** Upper bound for waiting on a rotation started by an unloaded page. */
export const MAX_ROTATION_WAIT_MS = 8_000;
const POLL_INTERVAL_MS = 100;

interface MarkerStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

interface LockManagerLike {
  request<T>(name: string, callback: () => Promise<T>): Promise<T>;
}

export interface CoordinatorEnv {
  storage: MarkerStorage | null;
  readCsrf: () => string | null;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  locks: LockManagerLike | null;
}

interface RotationMarker {
  id: string;
  fp: string;
  at: number;
}

/** FNV-1a 32-bit — a short, non-reversible tag; NOT a security primitive. */
export function fingerprint(value: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

export function defaultEnv(): CoordinatorEnv {
  let storage: MarkerStorage | null = null;
  try {
    storage = window.localStorage;
  } catch {
    storage = null;
  }
  const locks =
    typeof navigator !== "undefined" && "locks" in navigator && navigator.locks
      ? (navigator.locks as unknown as LockManagerLike)
      : null;
  return {
    storage,
    readCsrf: readCsrfToken,
    now: () => Date.now(),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    locks,
  };
}

function readMarker(env: CoordinatorEnv): RotationMarker | null {
  try {
    const raw = env.storage?.getItem(ROTATION_MARKER_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<RotationMarker>;
    if (typeof parsed.id === "string" && typeof parsed.fp === "string" && typeof parsed.at === "number") {
      return parsed as RotationMarker;
    }
  } catch {
    /* corrupt or blocked storage — treat as absent */
  }
  removeMarker(env);
  return null;
}

function removeMarker(env: CoordinatorEnv): void {
  try {
    env.storage?.removeItem(ROTATION_MARKER_KEY);
  } catch {
    /* storage unavailable */
  }
}

function currentFingerprint(env: CoordinatorEnv): string | null {
  const csrf = env.readCsrf();
  return csrf ? fingerprint(csrf) : null;
}

/**
 * If a rotation started by another (possibly unloaded) page is still in
 * flight, wait until the CSRF cookie rotates or the bounded timeout elapses.
 */
async function waitForPendingRotation(env: CoordinatorEnv): Promise<void> {
  const marker = readMarker(env);
  if (!marker) return;
  const deadline = marker.at + MAX_ROTATION_WAIT_MS;
  if (env.now() >= deadline) {
    removeMarker(env);
    return;
  }
  while (currentFingerprint(env) === marker.fp) {
    if (env.now() >= deadline) {
      removeMarker(env);
      return;
    }
    await env.sleep(POLL_INTERVAL_MS);
  }
}

function markRotationStarted(env: CoordinatorEnv): string | null {
  const fp = currentFingerprint(env);
  if (!fp) return null;
  const id =
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : `${env.now()}-${Math.random().toString(16).slice(2)}`;
  try {
    env.storage?.setItem(ROTATION_MARKER_KEY, JSON.stringify({ id, fp, at: env.now() }));
    return id;
  } catch {
    return null;
  }
}

function clearOwnMarker(env: CoordinatorEnv, id: string | null): void {
  if (!id) return;
  const marker = readMarker(env);
  if (marker?.id === id) removeMarker(env);
}

function hasHttpStatus(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    typeof (error as { status?: unknown }).status === "number"
  );
}

/** Run `send` (the actual refresh request) under cross-tab coordination. */
export async function coordinateRefresh<T>(
  send: () => Promise<T>,
  env: CoordinatorEnv = defaultEnv(),
): Promise<T> {
  const run = async () => {
    await waitForPendingRotation(env);
    const id = markRotationStarted(env);
    try {
      const result = await send();
      clearOwnMarker(env, id);
      return result;
    } catch (error) {
      // Only an HTTP answer proves the rotation is settled. An abort or a
      // network error (typically: this page is being unloaded) may mean the
      // keepalive request is still completing — keep the marker so the next
      // page waits for it; it expires after MAX_ROTATION_WAIT_MS anyway.
      if (hasHttpStatus(error)) clearOwnMarker(env, id);
      throw error;
    }
  };
  return env.locks ? env.locks.request(REFRESH_LOCK_NAME, run) : run();
}
