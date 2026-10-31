import { Outlet, Route, Routes } from "react-router";

import { AuthProvider } from "@/auth/AuthProvider";
import { ProtectedRoute } from "@/auth/ProtectedRoute";
import { AppShell } from "@/components/layout/AppShell";
import { DemoArea } from "@/demo/DemoArea";
import { config } from "@/lib/config";
import { AnalyzePage } from "@/pages/AnalyzePage";
import { BatchAnalyzePage } from "@/pages/BatchAnalyzePage";
import { CachePage } from "@/pages/CachePage";
import { DashboardPage } from "@/pages/DashboardPage";
import { LoginPage } from "@/pages/LoginPage";
import { NotFoundPage } from "@/pages/NotFoundPage";
import { ProvidersPage } from "@/pages/ProvidersPage";
import { ReportPage } from "@/pages/ReportPage";

/**
 * Routing.
 *
 * `/login` is always public. Every other application route is wrapped in
 * `<ProtectedRoute>`, which is a no-op when `VITE_AUTH_MODE` is "disabled"
 * (local demo) and an auth gate when it is "jwt".
 *
 * Every real route (including `/login` and the 404 page) renders inside the
 * real-app layout route, which mounts `<AuthProvider>` (silent refresh in
 * "jwt" mode) and `<AppShell>` (sidebar, backend health badge).
 *
 * `/demo/*` (mock multi-user UI prototype) is only registered when
 * `VITE_PROTOTYPE_MODE` is enabled; otherwise it falls through to the 404
 * route. It sits OUTSIDE the real-app layout: neither `AuthProvider` nor
 * `AppShell` is mounted for it, so it never triggers `/auth/refresh`, the
 * health check or any other backend request. It has its own demo shell and
 * demo session and is NOT wrapped in `<ProtectedRoute>`.
 */
function RealAppLayout() {
  return (
    <AuthProvider>
      <AppShell>
        <Outlet />
      </AppShell>
    </AuthProvider>
  );
}

export function AppRoutes() {
  return (
    <Routes>
      {config.prototypeMode ? (
        <Route path="/demo/*" element={<DemoArea />} />
      ) : null}
      <Route element={<RealAppLayout />}>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <DashboardPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/analyze"
          element={
            <ProtectedRoute>
              <AnalyzePage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/analyze/batch"
          element={
            <ProtectedRoute>
              <BatchAnalyzePage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/providers"
          element={
            <ProtectedRoute>
              <ProvidersPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/cache"
          element={
            <ProtectedRoute>
              <CachePage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/reports/:reportId"
          element={
            <ProtectedRoute>
              <ReportPage />
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
