import type { ReactNode } from "react";
import { NavLink } from "react-router";

import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";

const MOBILE_NAV = [
  { to: "/", label: "Ana Sayfa", end: true },
  { to: "/analyze", label: "Analiz", end: true },
  { to: "/analyze/batch", label: "Toplu", end: false },
  { to: "/providers", label: "Provider'lar", end: false },
  { to: "/cache", label: "Cache", end: false },
];

/** Uygulama düzeni: sidebar + topbar + kaydırılabilir içerik alanı. */
export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-full min-h-screen bg-surface">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="flex-1 overflow-y-auto p-4 md:p-6">{children}</main>
        {/* Kompakt mobil navigasyon — sidebar md altında gizlenir. */}
        <nav
          className="flex border-t border-surface-border bg-surface-raised pb-[env(safe-area-inset-bottom)] md:hidden"
          aria-label="Ana navigasyon (mobil)"
        >
          {MOBILE_NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `flex min-h-11 min-w-0 flex-1 items-center justify-center whitespace-nowrap px-0.5 text-center text-[11px] min-[360px]:text-xs ${
                  isActive ? "text-accent font-medium" : "text-slate-400"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </div>
    </div>
  );
}