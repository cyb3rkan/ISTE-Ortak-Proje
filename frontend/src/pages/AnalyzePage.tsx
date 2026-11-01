import { Link } from "react-router";

import { Card } from "@/components/common/Card";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { EnrichForm } from "@/components/enrich/EnrichForm";
import { EnrichmentResult } from "@/components/enrich/EnrichmentResult";
import { useReportAudience } from "@/components/report/useReportAudience";
import { useEnrich } from "@/hooks/useEnrich";

export function AnalyzePage() {
  const { data, error, loading, run } = useEnrich();
  const audience = useReportAudience();

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100">IOC Analizi</h1>
          <p className="mt-1 text-sm text-slate-400">
            Threat intelligence enrichment için tek bir indicator gönderin.
          </p>
        </div>
        <Link
          to="/analyze/batch"
          className="text-sm text-accent hover:underline"
        >
          Toplu analiz →
        </Link>
      </div>

      <Card title="Yeni Analiz">
        <EnrichForm onSubmit={run} submitting={loading} />
      </Card>

      {loading ? <LoadingState label="Provider'lar sorgulanıyor…" /> : null}

      {error ? <ErrorState message={error} /> : null}

      {data ? (
        <EnrichmentResult result={data} audience={audience} />
      ) : !loading && !error ? (
        <EmptyState
          title="Henüz analiz yok"
          description="Yukarıya bir IOC girin ve sonuçları görmek için 'Analiz Et' butonuna tıklayın."
        />
      ) : null}
    </div>
  );
}