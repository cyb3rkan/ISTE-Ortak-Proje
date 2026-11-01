import { createContext, useContext } from "react";

import type { AuthContextValue } from "./authTypes";

/**
 * Auth context. Default value throws if a consumer is mounted outside the
 * provider — a programming error we want to surface loudly in development.
 */
export const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (ctx === null) {
    throw new Error("useAuth must be used within an <AuthProvider>");
  }
  return ctx;
}
