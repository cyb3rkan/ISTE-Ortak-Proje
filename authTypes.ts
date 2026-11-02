/**
 * Types for the browser auth layer.
 *
 * Mirrors the backend `/auth/*` DTOs (see web/api/routers/auth.py).
 */

export type UserRole = "admin" | "analyst";

export interface AuthUser {
  username: string;
  role: string;
}

/** Body of POST /auth/login and /auth/refresh. */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: AuthUser;
}

export interface LoginRequest {
  username: string;
  password: string;
}

/**
 * The in-memory auth state.
 *
 * SECURITY: `accessToken` is held in React state / a module variable only.
 * It is NEVER written to localStorage or sessionStorage. The refresh token
 * lives exclusively in an httpOnly cookie the JS cannot read.
 */
export interface AuthState {
  status: "unknown" | "anonymous" | "authenticated";
  user: AuthUser | null;
}

export interface AuthContextValue extends AuthState {
  login: (credentials: LoginRequest) => Promise<void>;
  logout: () => Promise<void>;
  /** Returns the current in-memory access token, or null. */
  getAccessToken: () => string | null;
}
