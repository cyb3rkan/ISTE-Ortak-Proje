/**
 * In-memory access-token holder.
 *
 * SECURITY: this is a plain module-scoped variable. The access token is
 * deliberately NOT placed in localStorage or sessionStorage — a token in web
 * storage is readable by any injected script (XSS) and survives across tabs
 * and restarts. Keeping it in memory means it is gone on a full page reload;
 * the httpOnly refresh cookie is used to transparently obtain a new one.
 *
 * The API client (`lib/api.ts`) reads from here to attach the Bearer header
 * and to drive its single-shot 401 -> refresh -> retry flow, without taking a
 * direct dependency on React state.
 */

import { refreshRequest } from "./authApi";
import { coordinateRefresh } from "./refreshCoordinator";

let accessToken: string | null = null;
// Bumped on every explicit token change (login, refresh, logout). Lets a
// refresh that started earlier detect that a newer session state exists.
let tokenGeneration = 0;

/** A callback invoked whenever a refresh ultimately fails (forces logout). */
let onSessionLost: (() => void) | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
  tokenGeneration += 1;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function clearAccessToken(): void {
  accessToken = null;
  tokenGeneration += 1;
}

export function setSessionLostHandler(handler: (() => void) | null): void {
  onSessionLost = handler;
}

// De-duplicate concurrent refreshes within this tab: if several requests 401
// at once they all await the same in-flight refresh promise. Across tabs and
// page loads, refreshes are coordinated by refreshCoordinator.
let refreshInFlight: Promise<string | null> | null = null;

/**
 * Attempt to refresh the access token using the httpOnly refresh cookie.
 * Returns the new token on success, or null on failure (and triggers the
 * session-lost handler).
 */
export async function tryRefreshAccessToken(): Promise<string | null> {
  if (refreshInFlight) return refreshInFlight;

  const startedAt = tokenGeneration;
  refreshInFlight = (async () => {
    try {
      const result = await coordinateRefresh(refreshRequest);
      setAccessToken(result.access_token);
      return result.access_token;
    } catch {
      // A failure that arrives after a newer token was set (e.g. the user
      // logged in while the page-load refresh was pending) is stale: it must
      // not wipe the newer session.
      if (tokenGeneration !== startedAt) return accessToken;
      clearAccessToken();
      if (onSessionLost) onSessionLost();
      return null;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}
