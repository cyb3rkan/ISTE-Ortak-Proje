/**
 * Post-login redirect target sanitiser.
 *
 * SECURITY: the login page sends the user back to the path they originally
 * requested (`location.state.from`, captured from the URL by ProtectedRoute).
 * That path is attacker-influenced — a crafted link such as `//evil.example`
 * or `/\evil.example` could turn the post-login navigation into an open
 * redirect (cf. react-router advisories fixed only in v7). We therefore only
 * accept same-origin, in-app absolute paths and fall back to "/" otherwise.
 */

const FALLBACK = "/";
const PROBE_ORIGIN = "http://app.invalid";

// Backslashes, ASCII control characters and whitespace have no place in an
// in-app route and are the usual ingredients of URL-parser confusion.
const FORBIDDEN_CHARS = /[\\\u0000-\u001f\u007f\s]/;

export function safeRedirectPath(value: unknown): string {
  if (typeof value !== "string" || value === "") return FALLBACK;
  if (!value.startsWith("/") || value.startsWith("//")) return FALLBACK;
  if (FORBIDDEN_CHARS.test(value)) return FALLBACK;

  // Reject encoded variants of the same tricks (`/%2F/host`, `/%5Chost`).
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return FALLBACK;
  }
  if (decoded.startsWith("//") || FORBIDDEN_CHARS.test(decoded)) return FALLBACK;

  // Final check with the platform URL parser: must stay on our origin.
  let url: URL;
  try {
    url = new URL(value, PROBE_ORIGIN);
  } catch {
    return FALLBACK;
  }
  if (url.origin !== PROBE_ORIGIN) return FALLBACK;
  if (url.pathname === "/login") return FALLBACK;

  return value;
}
