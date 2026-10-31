import type { ReactNode } from "react";

interface DemoAuthCardProps {
  title: string;
  /** Başlığın altında gösterilen demo açıklaması. */
  description: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
}

/** Demo hesap ekranlarının ortak kart düzeni (demo giriş ekranıyla aynı dil). */
export function DemoAuthCard({ title, description, children, footer }: DemoAuthCardProps) {
  return (
    <section className="mx-auto w-full max-w-md rounded-lg border border-surface-border bg-surface-raised">
      <header className="border-b border-surface-border px-5 py-4">
        <div className="flex items-center gap-2">
          <span className="text-accent text-lg font-bold" aria-hidden>
            ◆
          </span>
          <h1 className="text-sm font-semibold text-slate-100">{title}</h1>
        </div>
        <div className="mt-2 text-xs text-slate-400">{description}</div>
      </header>
      <div className="p-5">{children}</div>
      {footer ? (
        <footer className="border-t border-surface-border px-5 py-3 text-center text-xs text-slate-400">
          {footer}
        </footer>
      ) : null}
    </section>
  );
}

/** Demo ekranlarında birincil eylem butonunun ortak stili. */
export const DEMO_PRIMARY_BUTTON =
  "w-full rounded-md bg-accent px-4 py-2 text-sm font-semibold text-slate-900 transition hover:bg-accent/90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-60";

/** Demo ekranlarında metin bağlantısı stili. */
export const DEMO_LINK =
  "text-accent hover:underline focus-visible:outline-2 focus-visible:outline-accent";

/** Demo ekranlarında hata kutusu stili. */
export const DEMO_ALERT =
  "rounded-md border border-risk-critical/40 bg-risk-critical/10 px-3 py-2 text-xs text-risk-critical";

/** Demo ekranlarında başarı/bilgi kutusu stili. */
export const DEMO_SUCCESS =
  "rounded-md border border-risk-low/40 bg-risk-low/10 px-3 py-2 text-xs text-slate-200";
