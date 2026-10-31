/**
 * Demo prototipi kabuğu.
 *
 * Gerçek `AppShell`'in yerine yalnızca `/demo` altında kullanılır: gerçek
 * kenar çubuğunu, mobil navigasyonu ve backend sağlık göstergesini içermez,
 * backend'e istek atmaz. Mevcut renk ve tipografi dilini korur.
 */

import type { ReactNode } from "react";
import { Link, NavLink } from "react-router";

import { useDemoSession } from "./useDemoSession";

const DEMO_NAV = [
  { to: "/demo/dashboard", label: "Kontrol Paneli", adminOnly: false },
  { to: "/demo/api-keys", label: "API Anahtarlarım", adminOnly: false },
  // Yalnızca demo yönetici oturumunda gösterilir (arayüz kolaylığı; güvenlik değil).
  { to: "/demo/admin/users", label: "Kullanıcı yönetimi", adminOnly: true },
];

export function DemoShell({ children }: { children: ReactNode }) {
  const { session } = useDemoSession();

  return (
    <div className="flex min-h-screen flex-col bg-surface">
      <header className="flex h-14 items-center justify-between gap-2 border-b border-surface-border bg-surface-raised px-3 sm:px-4">
        <div className="flex min-w-0 items-center gap-2 whitespace-nowrap">
          <span className="text-accent text-lg font-bold" aria-hidden>
            ◆
          </span>
          <span className="font-semibold tracking-tight">IOC Enricher</span>
          <span className="rounded-sm border border-risk-medium/50 px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wide text-risk-medium">
            Demo
          </span>
        </div>
        <Link
          to="/"
          className="whitespace-nowrap rounded-md border border-surface-border bg-surface px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-accent/50 focus-visible:outline-2 focus-visible:outline-accent"
        >
          Gerçek uygulamaya dön
        </Link>
      </header>
      {session ? (
        <nav
          aria-label="Demo navigasyonu"
          className="flex flex-wrap gap-x-1 border-b border-surface-border bg-surface-raised px-3 sm:px-4"
        >
          {DEMO_NAV.filter((item) => !item.adminOnly || session.account.role === "admin").map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex min-h-11 items-center whitespace-nowrap border-b-2 px-2 text-sm sm:px-3 focus-visible:outline-2 focus-visible:outline-accent ${
                  isActive
                    ? "border-accent font-medium text-accent"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      ) : null}
      <main className="flex-1 p-4 md:p-6">
        <div className="mx-auto w-full max-w-5xl space-y-4">{children}</div>
      </main>
    </div>
  );
}
