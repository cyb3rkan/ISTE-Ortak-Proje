/**
 * Route guard.
 *
 * In `disabled` auth mode it is a pass-through (local demo). In `jwt` mode it
 * gates children behind authentication:
 *  - while the initial silent refresh is in flight -> a loading state.
 *  - anonymous -> redirect to /login, preserving the attempted path so the
 *    user lands back where they intended after signing in.
 *  - authenticated -> render the children.
 */

import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router";

import { LoadingState } from "@/components/common/LoadingState";
import { config } from "@/lib/config";
import { useAuth } from "./useAuth";

export function ProtectedRoute({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();

  if (config.authMode !== "jwt") {
    return <>{children}</>;
  }

  if (status === "unknown") {
    return <LoadingState label="Restoring your session…" />;
  }

  if (status === "anonymous") {
    return (
      <Navigate to="/login" replace state={{ from: location.pathname }} />
    );
  }

  return <>{children}</>;
}
