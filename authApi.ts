/**
 * Low-level auth endpoint calls.
 *
 * These are deliberately separate from `lib/api.ts`:
 *  - They must run *before* an access token exists (login) or *without* one
 *    (refresh), so they cannot depend on the token-injecting client.
 *  - `credentials: "include"` is required so the browser sends/receives the
 *    httpOnly refresh cookie.
 *  - refresh/logout send the CSRF token (read from the readable CSRF cookie)
 *    in the `X-CSRF-Token` header — the double-submit-cookie pattern.
 *
 * No token is ever persisted here; the caller keeps the access token in
 * memory only.
 */

import { apiUrl } from "@/lib/config";
import type { AuthUser, LoginRequest, TokenResponse } from "./authTypes";

/** Name of the readable CSRF cookie the backend sets on login. */
const CSRF_COOKIE_NAME = "ioc_csrf_token";

export class AuthApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "AuthApiError";
    this.status = status;
  }
}

/** Read the (non-httpOnly) CSRF cookie. Returns null when absent. */
export function readCsrfToken(): string | null {
  const match = document.cookie
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${CSRF_COOKIE_NAME}=`));
  if (!match) return null;
  const value = match.slice(CSRF_COOKIE_NAME.length + 1);
  return value || null;
}

async function parseJsonOrThrow(
  response: Response,
  fallbackMessage: string,
): Promise<TokenResponse> {
  const contentType = response.headers.get("content-type") ?? "";
  const isJson =
    contentType.includes("application/json") ||
    contentType.includes("application/problem+json");

  if (!response.ok) {
    let detail = fallbackMessage;
    if (isJson) {
      try {
        const body: unknown = await response.json();
        if (body && typeof body === "object") {
          const rec = body as Record<string, unknown>;
          if (typeof rec.detail === "string") detail = rec.detail;
        }
      } catch {
        /* keep fallback */
      }
    }
    throw new AuthApiError(detail, response.status);
  }

  if (!isJson) {
    throw new AuthApiError("Unexpected response from the server.", response.status);
  }
  return (await response.json()) as TokenResponse;
}

/** POST /auth/login — returns the access token; sets cookies as a side effect. */
export async function loginRequest(
  credentials: LoginRequest,
): Promise<TokenResponse> {
  const response = await fetch(apiUrl("/auth/login"), {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(credentials),
  });
  return parseJsonOrThrow(response, "Invalid username or password.");
}

/**
 * POST /auth/refresh — uses the refresh cookie + CSRF header.
 *
 * `keepalive` lets the request finish even if the page is unloaded mid-flight
 * (reload / navigation). Refresh tokens are single-use: without it the server
 * would rotate the token while the browser discarded the response and its
 * new cookie, logging the user out. Call via tokenStore (coordinated).
 */
export async function refreshRequest(): Promise<TokenResponse> {
  const csrf = readCsrfToken();
  const response = await fetch(apiUrl("/auth/refresh"), {
    method: "POST",
    credentials: "include",
    keepalive: true,
    headers: {
      Accept: "application/json",
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
    },
  });
  return parseJsonOrThrow(response, "Session expired. Please sign in again.");
}

/**
 * GET /auth/me — returns the current user for a given access token.
 * Used to hydrate user state after a silent refresh on page load.
 */
export async function fetchMe(accessToken: string): Promise<AuthUser> {
  const response = await fetch(apiUrl("/auth/me"), {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${accessToken}`,
    },
  });
  if (!response.ok) {
    throw new AuthApiError("Could not load the current user.", response.status);
  }
  return (await response.json()) as AuthUser;
}

/** POST /auth/logout — clears cookies + revokes the refresh token. */
export async function logoutRequest(): Promise<void> {
  const csrf = readCsrfToken();
  try {
    await fetch(apiUrl("/auth/logout"), {
      method: "POST",
      credentials: "include",
      headers: {
        Accept: "application/json",
        ...(csrf ? { "X-CSRF-Token": csrf } : {}),
      },
    });
  } catch {
    // Logout is best-effort on the client; the local state is cleared either
    // way by the caller.
  }
}
