import { Link } from "react-router";

import { BatchForm } from "@/components/batch/BatchForm";
import { BatchResultsTable } from "@/components/batch/BatchResultsTable";
import { BatchSummary } from "@/components/batch/BatchSummary";
import { Card } from "@/components/common/Card";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { useEnrichBatch } from "@/hooks/useEnrichBatch";

export function BatchAnalyzePage() {
  const { data, error, loading, run } = useEnrichBatch();

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Toplu Analiz</h1>
          <p className="mt-1 text-sm text-slate-400">
            Tek bir istekte 50 adede kadar indicator için enrichment işlemi yapın.
          </p>
        </div>
        <Link
          to="/analyze"
          className="text-sm text-accent hover:underline"
        >
          ← Tekli analiz
        </Link>
      </div>

      <Card title="Yeni Toplu Analiz">
        <BatchForm onSubmit={run} submitting={loading} />
      </Card>

      {loading ? <LoadingState label="Toplu enrichment işlemi yapılıyor…" /> : null}
      {error ? <ErrorState message={error} /> : null}

      {data ? (
        <>
          <BatchSummary summary={data.summary} />
          <BatchResultsTable results={data.results} errors={data.errors} />
        </>
      ) : null}
    </div>
  );
}