interface StatusBadgeProps {
  /** Görsel durum tonu. */
  tone: "ok" | "warn" | "error" | "neutral";
  label: string;
  /** Compact text shown below the `sm` breakpoint (full label stays the accessible name). */
  shortLabel?: string;
  title?: string;
}

const TONE_CLASSES: Record<StatusBadgeProps["tone"], string> = {
  ok: "bg-risk-low/15 text-risk-low border-risk-low/40",
  warn: "bg-risk-medium/15 text-risk-medium border-risk-medium/40",
  error: "bg-risk-critical/15 text-risk-critical border-risk-critical/40",
  neutral: "bg-slate-500/15 text-slate-300 border-slate-500/40",
};

export function StatusBadge({ tone, label, shortLabel, title }: StatusBadgeProps) {
  return (
    <span
      role="status"
      aria-label={label}
      title={title}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs font-medium ${TONE_CLASSES[tone]}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
      {shortLabel ? (
        <>
          <span className="sm:hidden" aria-hidden>
            {shortLabel}
          </span>
          <span className="hidden sm:inline" aria-hidden>
            {label}
          </span>
        </>
      ) : (
        <span aria-hidden>{label}</span>
      )}
    </span>
  );
}