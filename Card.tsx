import type { ReactNode } from "react";

interface CardProps {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}

/** Temel yüzey kartı — her dashboard paneli için düzen birimi. */
export function Card({ title, action, children, className = "" }: CardProps) {
  return (
    <section
      className={`rounded-lg border border-surface-border bg-surface-raised ${className}`}
    >
      {title || action ? (
        <header className="flex items-center justify-between border-b border-surface-border px-4 py-3">
          {typeof title === "string" ? (
            <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
          ) : (
            title
          )}
          {action}
        </header>
      ) : null}
      <div className="p-4">{children}</div>
    </section>
  );
}