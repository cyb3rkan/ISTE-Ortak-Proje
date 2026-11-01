import { Card } from "@/components/common/Card";
import type { BatchSummary as BatchSummaryType } from "@/types/api";

function num(value: unknown): number {
  return typeof value === "number" ? value : 0;
}

function Stat({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: number;
  tone?: "default" | "ok" | "warn" | "error";
}) {
  const toneClass =
    tone === "ok"
      ? "text-risk-low"
      : tone === "warn"
        ? "text-risk-medium"
        : tone === "error"
          ? "text-risk-critical"
          : "text-slate-100";
  return (
    <div className="rounded-md border border-surface-border bg-surface p-3 text-center">
      <p className={`font-mono text-2xl font-bold ${toneClass}`}>{value}</p>
      <p className="mt-0.5 text-xs uppercase tracking-wide text-slate-500">
        {label}
      </p>
    </div>
  );
}

export function BatchSummary({
  summary,
}: {
  summary: Partial<BatchSummaryType> & Record<string, unknown>;
}) {
  return (
    <Card title="Toplu Özet">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <Stat label="Toplam" value={num(summary.total)} />
        <Stat label="Başarılı" value={num(summary.success)} tone="ok" />
        <Stat label="Başarısız" value={num(summary.failed)} tone="error" />
        <Stat
          label="Tekrar"
          value={num(summary.duplicates_removed)}
          tone="warn"
        />
        <Stat label="Benzersiz" value={num(summary.unique)} />
      </div>
    </Card>
  );
}
