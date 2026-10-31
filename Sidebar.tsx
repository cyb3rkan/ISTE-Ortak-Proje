import { NavLink } from "react-router";

const NAV_ITEMS = [
  { to: "/", label: "Kontrol Paneli", end: true },
  { to: "/analyze", label: "Analiz", end: true },
  { to: "/analyze/batch", label: "Toplu", end: false },
  { to: "/providers", label: "Provider'lar", end: false },
  { to: "/cache", label: "Cache", end: false },
];

export function Sidebar() {
  return (
    <aside className="hidden w-56 shrink-0 border-r border-surface-border bg-surface-raised md:block">
      <div className="flex h-14 items-center gap-2 border-b border-surface-border px-4">
        <span className="text-accent text-lg font-bold">◆</span>
        <span className="font-semibold tracking-tight">IOC Enricher</span>
      </div>
      <nav className="flex flex-col gap-1 p-3" aria-label="Primary">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `rounded-md px-3 py-2 text-sm transition-colors ${
                isActive
                  ? "bg-accent/10 text-accent font-medium"
                  : "text-slate-400 hover:bg-slate-700/30 hover:text-slate-200"
              }`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}