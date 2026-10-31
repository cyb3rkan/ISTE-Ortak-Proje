/**
 * `/demo/*` alt uygulaması.
 *
 * Yalnızca `config.prototypeMode` açıkken `routes.tsx` tarafından bağlanır.
 * Kendi `DemoSessionProvider`'ını ve `DemoAccountFlowProvider`'ını taşır;
 * gerçek `ProtectedRoute` veya `AuthProvider` kullanılmaz, böylece demo ve
 * gerçek oturum birbirine karışmaz. Gerçek `AppShell` yerine `DemoShell`
 * kullanılır.
 */

import type { ReactNode } from "react";
import { Navigate, Route, Routes, useNavigate } from "react-router";

import { NotFoundPage } from "@/pages/NotFoundPage";
import { DemoAccountFlowProvider } from "./DemoAccountFlowProvider";
import { DemoAdminUsersProvider } from "./DemoAdminUsersProvider";
import { DemoApiKeysProvider } from "./DemoApiKeysProvider";
import { DemoSessionProvider } from "./DemoSessionProvider";
import { DemoShell } from "./DemoShell";
import { DEMO_ROLE_LABELS } from "./demoTypes";
import { DemoAccessDeniedPage } from "./pages/DemoAccessDeniedPage";
import { DemoAdminUsersPage } from "./pages/DemoAdminUsersPage";
import { DemoApiKeysPage } from "./pages/DemoApiKeysPage";
import { DemoDashboardPage } from "./pages/DemoDashboardPage";
import { DemoForgotPasswordPage } from "./pages/DemoForgotPasswordPage";
import { DemoLoginPage } from "./pages/DemoLoginPage";
import { DemoProviderGuidePage } from "./pages/DemoProviderGuidePage";
import { DemoResetPasswordPage } from "./pages/DemoResetPasswordPage";
import { DemoSignupPage } from "./pages/DemoSignupPage";
import { DemoVerifyEmailPage } from "./pages/DemoVerifyEmailPage";
import { useDemoSession } from "./useDemoSession";

export function DemoArea() {
  return (
    <DemoSessionProvider>
      <DemoAccountFlowProvider>
        <DemoApiKeysProvider>
          <DemoAdminUsersProvider>
            <DemoShell>
              <DemoBanner />
              <Routes>
                <Route index element={<Navigate to="dashboard" replace />} />
                <Route path="login" element={<DemoLoginPage />} />
                <Route path="signup" element={<DemoSignupPage />} />
                <Route path="verify-email" element={<DemoVerifyEmailPage />} />
                <Route path="forgot-password" element={<DemoForgotPasswordPage />} />
                <Route path="reset-password" element={<DemoResetPasswordPage />} />
                <Route
                  path="dashboard"
                  element={
                    <RequireDemoSession>
                      <DemoDashboardPage />
                    </RequireDemoSession>
                  }
                />
                <Route
                  path="api-keys"
                  element={
                    <RequireDemoSession>
                      <DemoApiKeysPage />
                    </RequireDemoSession>
                  }
                />
                <Route
                  path="api-keys/guides/:providerId"
                  element={
                    <RequireDemoSession>
                      <DemoProviderGuidePage />
                    </RequireDemoSession>
                  }
                />
                <Route
                  path="admin/users"
                  element={
                    <RequireDemoSession>
                      <RequireDemoAdmin>
                        <DemoAdminUsersPage />
                      </RequireDemoAdmin>
                    </RequireDemoSession>
                  }
                />
                <Route path="*" element={<NotFoundPage />} />
              </Routes>
            </DemoShell>
          </DemoAdminUsersProvider>
        </DemoApiKeysProvider>
      </DemoAccountFlowProvider>
    </DemoSessionProvider>
  );
}

/** Demo oturumu yoksa demo girişine yönlendirir. Bir güvenlik kontrolü değildir. */
function RequireDemoSession({ children }: { children: ReactNode }) {
  const { session } = useDemoSession();
  if (!session) {
    return <Navigate to="/demo/login" replace />;
  }
  return <>{children}</>;
}

/**
 * Yalnızca demo `admin` oturumunda çocukları render eder; aksi halde korunan
 * sayfa hiç mount edilmez ve erişim reddi gösterilir. Bir güvenlik kontrolü
 * değildir — gerçek yetkilendirme backend'de uygulanmalıdır.
 */
function RequireDemoAdmin({ children }: { children: ReactNode }) {
  const { session } = useDemoSession();
  if (session?.account.role !== "admin") {
    return <DemoAccessDeniedPage />;
  }
  return <>{children}</>;
}

/** Her demo sayfasında görünen prototip uyarısı ve demo oturum kontrolü. */
function DemoBanner() {
  const { session, endSession } = useDemoSession();
  const navigate = useNavigate();

  async function handleEndSession() {
    await endSession();
    navigate("/demo/login", { replace: true });
  }

  return (
    <section
      aria-label="Demo prototipi bildirimi"
      className="flex flex-col gap-3 rounded-lg border border-risk-medium/40 bg-risk-medium/10 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="flex min-w-0 items-start gap-2">
        <span className="shrink-0 rounded-sm border border-risk-medium/50 px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wide text-risk-medium">
          Demo prototipi
        </span>
        <p className="text-xs text-slate-300">
          Bu alandaki hesaplar ve işlemler sahtedir. Gerçek kimlik doğrulama
          yapılmaz ve backend'e veri gönderilmez.
        </p>
      </div>
      {session ? (
        <div className="flex flex-wrap items-center justify-between gap-2 sm:shrink-0 sm:justify-end">
          <span className="whitespace-nowrap text-xs text-slate-400">
            {session.account.displayName}
            <span className="ml-1 rounded-sm bg-slate-700/50 px-1.5 py-0.5 text-slate-300">
              {DEMO_ROLE_LABELS[session.account.role]}
            </span>
          </span>
          <button
            type="button"
            onClick={handleEndSession}
            className="whitespace-nowrap rounded-md border border-surface-border bg-surface px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-accent/50 focus-visible:outline-2 focus-visible:outline-accent"
          >
            Demo oturumunu kapat
          </button>
        </div>
      ) : null}
    </section>
  );
}
