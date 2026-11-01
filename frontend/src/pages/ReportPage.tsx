import { useId, useState } from "react";
import { useParams } from "react-router";

import { Card } from "@/components/common/Card";
import { CopyButton } from "@/components/common/CopyButton";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { asEnrichmentDTO } from "@/components/report/enrichmentShape";
import { formatTimestamp } from "@/components/report/reportLanguage";
import { ReportView } from "@/components/report/ReportView";
import { useReportAudience } from "@/components/report/useReportAudience";
import { getReport } from "@/lib/api";
import {
  downloadTextFile,
  extensionForFormat,
  safeFilename,
} from "@/lib/download";
import { prettyJson, revealInvisible } from "@/lib/safeRender";
import { useQuery } from "@/hooks/useAsync";
import type { ReportResponse } from "@/types/api";

/** Report içeriğini düz string olarak render et — asla HTML değil. */
function reportText(report: ReportResponse): string {
  if (report.format === "json") return prettyJson(report.content);
  return typeof report.content === "string"
    ? report.content
    : prettyJson(report.content);
}

/**
 * Ham rapor içeriği (yalnızca analist görünümü). Yapılandırılmış görünüm
 * gösterildiğinde içerik başlangıçta kapalıdır; kopyala/indir her zaman açıktır.
 */
function ReportBody({
  report,
  collapsible = false,
}: {
  report: ReportResponse;
  collapsible?: boolean;
}) {
  // Markdown, <pre> içinde DÜZ METİN olarak render edilir. Bilerek
  // HTML'e dönüştürülmez — markdown-to-HTML yok, dangerouslySetInnerHTML yok.
  // React string'i escape ettiği için gömülü markup yalnızca pasif metin olarak kalır.
  const text = reportText(report);
  const [open, setOpen] = useState(!collapsible);
  const contentId = useId();

  function handleDownload() {
    const ext = extensionForFormat(report.format);
    const mime = ext === "json" ? "application/json" : "text/plain";
    downloadTextFile(
      safeFilename(`report-${report.report_id}`, ext),
      text,
      mime,
    );
  }

  return (
    <Card
      title={`Ham rapor · ${report.format}`}
      action={
        <div className="flex flex-wrap gap-2">
          <span data-testid="report-copy">
            <CopyButton value={text} label="İçeriği kopyala" />
          </span>
          <button
            type="button"
            onClick={handleDownload}
            data-testid="report-download"
            className="rounded-sm border border-surface-border bg-surface px-2 py-1 text-xs text-slate-300 hover:border-accent/50"
          >
            Raporu indir
          </button>
        </div>
      }
    >
      {collapsible ? (
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls={contentId}
          className="mb-2 rounded-sm text-xs font-medium text-accent hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        >
          {open ? "Ham içeriği gizle" : "Ham içeriği göster"}
        </button>
      ) : null}
      {open ? (
        <pre
          id={contentId}
          className="max-h-[60vh] overflow-auto whitespace-pre-wrap wrap-break-word rounded-md border border-surface-border bg-surface p-3 font-mono text-xs text-slate-300"
        >
          {/* Görünmez karakterler yalnızca ekranda işaretlenir; kopya/indirme ham metni kullanır. */}
          {revealInvisible(text)}
        </pre>
      ) : null}
    </Card>
  );
}

function ReportContent({ report }: { report: ReportResponse }) {
  const audience = useReportAudience();
  const enrichment = report.format === "json" ? asEnrichmentDTO(report.content) : null;

  if (enrichment) {
    return (
      <div className="space-y-4">
        <ReportView result={enrichment} audience={audience} />
        {audience === "analyst" ? <ReportBody report={report} collapsible /> : null}
      </div>
    );
  }

  if (audience === "analyst") return <ReportBody report={report} />;

  // Günlük görünüm ham/teknik içeriği göstermez.
  return (
    <p
      role="status"
      data-testid="report-plain-unavailable"
      className="rounded-md border border-surface-border bg-surface-raised px-4 py-3 text-sm text-slate-300"
    >
      Bu rapor yalnızca teknik biçimde kaydedilmiş; sade bir özet gösterilemiyor. Sonucu
      anlaşılır biçimde görmek için göstergeyi Analiz sayfasında yeniden analiz edebilirsiniz.
    </p>
  );
}

export function ReportPage() {
  const { reportId } = useParams<{ reportId: string }>();
  const { data, error, loading, reload } = useQuery(
    (signal) => getReport(reportId ?? "", signal),
    [reportId],
  );
  const created = formatTimestamp(data?.created_at);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Rapor</h1>
        {created ? (
          <p className="mt-1 text-xs text-slate-400">Kaydedilme zamanı: {created}</p>
        ) : null}
        <p className="mt-1 break-all font-mono text-xs text-slate-500">
          {reportId}
        </p>
      </div>

      {loading ? <LoadingState label="Rapor yükleniyor…" /> : null}
      {error ? <ErrorState message={error} onRetry={reload} /> : null}
      {data ? <ReportContent report={data} /> : null}
    </div>
  );
}
