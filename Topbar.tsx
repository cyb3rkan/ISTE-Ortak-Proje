import { useNavigate } from "react-router";

import { useAuth } from "@/auth/useAuth";
import { useHealth } from "@/hooks/useHealth";
import { config } from "@/lib/config";
import { StatusBadge } from "./StatusBadge";

/** Canlı backend sağlık göstergesi ve (jwt modunda) Auth kontrolleri içeren üst bar. */
export function Topbar() {
  const { data, error, loading } = useHealth();
  const { status, user, logout } = useAuth();
  const navigate = useNavigate();

  let badge: React.ReactNode;
  if (loading) {
    badge = <StatusBadge tone="neutral" label="Backend kontrol ediliyor…" shortLabel="Kontrol…" />;
  } else if (error) {
    badge = (
      <StatusBadge
        tone="error"
        label="Backend erişilemiyor"
        shortLabel="Erişilemiyor"
        title={error}
      />
    );
  } else if (data) {
    badge = (
      <StatusBadge
        tone="ok"
        label={`Backend çevrimiçi · v${data.version}`}
        shortLabel="Çevrimiçi"
        title={`${data.providers_configured} provider yapılandırıldı`}
      />
    );
  } else {
    badge = <StatusBadge tone="neutral" label="Bilinmiyor" />;
  }

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  const showAuthControls =
    config.authMode === "jwt" && status === "authenticated";

  return (
    <header className="flex h-14 items-center justify-between gap-2 border-b border-surface-border bg-surface-raised px-3 sm:px-4">
      <div className="flex shrink-0 items-center gap-2 whitespace-nowrap md:hidden">
        <span className="text-accent text-lg font-bold">◆</span>
        <span className="font-semibold">IOC Enricher</span>
      </div>
      <h1 className="hidden text-sm font-medium text-slate-400 md:block">
        Threat Intelligence Konsolu
      </h1>
      <div className="flex min-w-0 items-center gap-2 sm:gap-3">
        {badge}
        {showAuthControls ? (
          <div className="flex items-center gap-2">
            {user ? (
              <span className="hidden text-xs text-slate-400 sm:inline">
                {user.username}
                <span className="ml-1 rounded-sm bg-slate-700/50 px-1.5 py-0.5 font-mono uppercase text-slate-300">
                  {user.role}
                </span>
              </span>
            ) : null}
            <button
              type="button"
              onClick={handleLogout}
              className="whitespace-nowrap rounded-md border border-surface-border bg-surface px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-accent/50"
            >
              Çıkış Yap
            </button>
          </div>
        ) : null}
      </div>
    </header>
  );
}