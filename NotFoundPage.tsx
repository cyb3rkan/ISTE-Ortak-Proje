import { Link } from "react-router";

export function NotFoundPage() {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <p className="font-mono text-5xl font-bold text-slate-700">404</p>
      <p className="mt-3 text-sm text-slate-400">
        Aradığınız sayfa mevcut değil.
      </p>
      <Link
        to="/"
        className="mt-4 rounded-md border border-surface-border bg-surface-raised px-4 py-2 text-sm text-accent hover:border-accent/50"
      >
        Kontrol paneline dön
      </Link>
    </div>
  );
}