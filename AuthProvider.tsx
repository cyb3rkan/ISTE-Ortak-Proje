/**
 * Auth provider — owns the in-memory auth state for the app.
 *
 * On mount (in `jwt` mode) it attempts a silent refresh: if the user still
 * has a valid httpOnly refresh cookie from a previous visit, they are
 * transparently signed back in without re-entering credentials. The access
 * token itself is never persisted — only the refresh cookie (httpOnly,
 * managed by the browser) survives a reload.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { config } from "@/lib/config";
import { fetchMe, loginRequest, logoutRequest } from "./authApi";
import type { AuthContextValue, AuthUser, LoginRequest } from "./authTypes";
import {
  clearAccessToken,
  getAccessToken,
  setAccessToken,
  setSessionLostHandler,
  tryRefreshAccessToken,
} from "./tokenStore";
import { AuthContext } from "./useAuth";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<
    "unknown" | "anonymous" | "authenticated"
  >(config.authMode === "jwt" ? "unknown" : "anonymous");
  const [user, setUser] = useState<AuthUser | null>(null);
  const mounted = useRef(true);

  const goAnonymous = useCallback(() => {
    clearAccessToken();
    setUser(null);
    setStatus("anonymous");
  }, []);

  // Wire the token store's "session lost" hook (fired when a refresh fails
  // mid-session) to drop us back to the anonymous state.
  useEffect(() => {
    setSessionLostHandler(() => {
      if (mounted.current) goAnonymous();
    });
    return () => setSessionLostHandler(null);
  }, [goAnonymous]);

  // Silent refresh on first load (jwt mode only).
  useEffect(() => {
    mounted.current = true;
    if (config.authMode !== "jwt") {
      return () => {
        mounted.current = false;
      };
    }
    void (async () => {
      const token = await tryRefreshAccessToken();
      if (!mounted.current) return;
      if (!token) {
        setStatus("anonymous");
        return;
      }
      // Hydrate user details from /auth/me using the freshly minted token.
      try {
        const me = await fetchMe(token);
        if (!mounted.current) return;
        setUser(me);
        setStatus("authenticated");
      } catch {
        if (!mounted.current) return;
        goAnonymous();
      }
    })();
    return () => {
      mounted.current = false;
    };
    // goAnonymous is stable (useCallback with no deps).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = useCallback(async (credentials: LoginRequest) => {
    const result = await loginRequest(credentials);
    setAccessToken(result.access_token);
    setUser(result.user);
    setStatus("authenticated");
  }, []);

  const logout = useCallback(async () => {
    await logoutRequest();
    goAnonymous();
  }, [goAnonymous]);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      user,
      login,
      logout,
      getAccessToken,
    }),
    [status, user, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
