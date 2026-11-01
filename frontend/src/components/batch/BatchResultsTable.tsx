import { useMemo, useState } from "react";
import { Link } from "react-router";

import { Card } from "@/components/common/Card";
import { RiskLevelBadge } from "@/components/risk/RiskLevelBadge";
import { normalizeRiskLevel } from "@/lib/format";
import { revealInvisible, toDisplayString } from "@/lib/safeRender";
import type { BatchErrorItem, EnrichmentDTO } from "@/types/api";

type RiskFilter = "all" | "critical" | "high" | "medium" | "low" | "failed";
type SortKey = "ioc" | "score" | "level";
type SortDir = "asc" | "desc";

interface BatchResultsTableProps {
  results: EnrichmentDTO[];
  errors: Array<BatchErrorItem & Record<string, unknown>>;
}

const FILTERS: Array<{ key: RiskFilter; label: string }> = [
  { key: "all", label: "Tümü" },
  { key: "critical", label: "Kritik" },
  { key: "high", label: "Yüksek" },
  { key: "medium", label: "Orta" },
  { key: "low", label: "Düşük" },
  { key: "failed", label: "Başarısız" },
];

// Backend error codes -> Turkish labels. Unknown codes are shown verbatim so
// new error types are never hidden.
const ERROR_TYPE_LABELS: Record<string, string> = {
  validation_error: "Doğrulama hatası",
  execution_error: "İşlem hatası",
  deadline_exceeded: "Süre aşımı",
  unknown_error: "Beklenmeyen hata",
};

function errorTypeLabel(code: string): string {
  return ERROR_TYPE_LABELS[code] ?? code;
}

function humanReviewFlag(result: EnrichmentDTO): boolean {
  return result.ai_analysis?.requires_human_review === true;
}

export function BatchResultsTable({
  results,
  errors,
}: BatchResultsTableProps) {
  const [filter, setFilter] = useState<RiskFilter>("all");
  const [sortKey, setSortKey] = useState<SortKey>("score");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const filteredResults = useMemo(() => {
    let rows = results;
    if (filter !== "all" && filter !== "failed") {
      rows = rows.filter(
        (r) => normalizeRiskLevel(r.risk.level).toLowerCase() === filter,
      );
    }
    const sorted = [...rows].sort((a, b) => {
      let cmp = 0;
      if (sortKey === "ioc") cmp = a.ioc.localeCompare(b.ioc);
      else if (sortKey === "level")
        cmp = normalizeRiskLevel(a.risk.level).localeCompare(
          normalizeRiskLevel(b.risk.level),
        );
      else cmp = a.risk.score - b.risk.score;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return sorted;
  }, [results, filter, sortKey, sortDir]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "ioc" ? "asc" : "desc");
    }
  }

  const sortIndicator = (key: SortKey) =>
    sortKey === key ? (sortDir === "asc" ? " ▲" : " ▼") : "";

  const showFailed = filter === "all" || filter === "failed";
  const showResults = filter !== "failed";

  return (
    <Card title="Toplu Sonuçlar">
      <div className="mb-3 flex flex-wrap gap-1.5">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            type="button"
            onClick={() => setFilter(f.key)}
            className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
              filter === f.key
                ? "border-accent/50 bg-accent/10 text-accent"
                : "border-surface-border bg-surface text-slate-400 hover:text-slate-200"
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {showResults ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-surface-border text-xs uppercase tracking-wide text-slate-500">
                <th className="px-2 py-2">
                  <button
                    type="button"
                    onClick={() => toggleSort("ioc")}
                    className="hover:text-slate-200"
                  >
                    IOC{sortIndicator("ioc")}
                  </button>
                </th>
                <th className="px-2 py-2">Tür</th>
                <th className="px-2 py-2">
                  <button
                    type="button"
                    onClick={() => toggleSort("score")}
                    className="hover:text-slate-200"
                  >
                    Skor{sortIndicator("score")}
                  </button>
                </th>
                <th className="px-2 py-2">
                  <button
                    type="button"
                    onClick={() => toggleSort("level")}
                    className="hover:text-slate-200"
                  >
                    Seviye{sortIndicator("level")}
                  </button>
                </th>
                <th className="px-2 py-2">Provider'lar</th>
                <th className="px-2 py-2">İnceleme</th>
                <th className="px-2 py-2">Rapor</th>
              </tr>
            </thead>
            <tbody>
              {filteredResults.length === 0 ? (
                <tr>
                  <td
                    colSpan={7}
                    className="px-2 py-4 text-center text-slate-500"
                  >
                    Bu filtreyle eşleşen sonuç yok.
                  </td>
                </tr>
              ) : (
                filteredResults.map((r, i) => (
                  <tr
                    key={`${r.ioc}-${i}`}
                    className="border-b border-surface-border/60"
                  >
                    <td className="max-w-[16rem] truncate px-2 py-2 font-mono text-slate-200">
                      {revealInvisible(r.ioc)}
                    </td>
                    <td className="px-2 py-2 text-slate-400">{r.ioc_type}</td>
                    <td className="px-2 py-2 font-mono text-slate-200">
                      {Math.round(r.risk.score)}
                    </td>
                    <td className="px-2 py-2">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <RiskLevelBadge level={r.risk.level} size="sm" />
                        {r.risk.evidence_status === "insufficient_data" ? (
                          <span
                            className="rounded-sm border border-risk-medium/40 bg-risk-medium/10 px-1.5 py-0.5 text-[11px] font-medium text-risk-medium"
                            title="Hiçbir provider kullanılabilir sonuç döndürmedi; düşük skor güvenli olduğu anlamına gelmez."
                          >
                            Yetersiz veri
                          </span>
                        ) : null}
                        {r.risk.evidence_status === "partial" ? (
                          <span
                            className="rounded-sm border border-slate-600/50 bg-slate-700/20 px-1.5 py-0.5 text-[11px] font-medium text-slate-300"
                            title={`Kısmi kapsam: ${
                              (r.risk.unavailable_providers ?? []).join(", ") ||
                              "bazı provider'lar"
                            } yanıt vermedi; sonuç yanıt veren provider'lara dayanıyor.`}
                          >
                            Kısmi
                          </span>
                        ) : null}
                      </div>
                    </td>
                    <td className="px-2 py-2 text-slate-400">
                      {r.providers.length}
                    </td>
                    <td className="px-2 py-2">
                      {humanReviewFlag(r) ? (
                        <span
                          className="text-risk-medium"
                          role="img"
                          aria-label="İnsan incelemesi gerekli"
                          title="İnsan incelemesi gerekli"
                        >
                          ⚠
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="px-2 py-2">
                      {r.report_id ? (
                        <Link
                          to={`/reports/${r.report_id}`}
                          className="text-accent hover:underline"
                        >
                          görüntüle
                        </Link>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      ) : null}

      {showFailed && errors.length > 0 ? (
        <div className="mt-4">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-risk-critical">
            Başarısız kayıtlar ({errors.length})
          </p>
          <ul className="space-y-1.5">
            {errors.map((err, i) => (
              <li
                key={i}
                className="rounded-md border border-risk-critical/30 bg-risk-critical/5 p-2.5"
              >
                <p className="break-all font-mono text-sm text-slate-200">
                  {revealInvisible(err.ioc)}
                </p>
                <p className="text-xs text-risk-critical">
                  {/* Backend-sanitised message — rendered as plain text. */}
                  {errorTypeLabel(err.error_type)}: {toDisplayString(err.message)}
                </p>
                {typeof err.request_id === "string" ? (
                  <p className="mt-0.5 font-mono text-[11px] text-slate-600">
                    request_id: {err.request_id}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </Card>
  );
}
