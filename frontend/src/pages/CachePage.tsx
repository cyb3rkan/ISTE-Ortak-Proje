import { CacheStatsCard } from "@/components/cache/CacheStatsCard";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { useCacheStats } from "@/hooks/useCacheStats";

export function CachePage() {
  const { data, error, loading, reload } = useCacheStats();

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Cache</h1>
        <p className="mt-1 text-sm text-slate-400">
          Enrichment sonuçları için cache istatistikleri.
        </p>
      </div>

      {loading ? <LoadingState label="Cache istatistikleri yükleniyor…" /> : null}
      {error ? <ErrorState message={error} onRetry={reload} /> : null}
      {data ? <CacheStatsCard stats={data} /> : null}
    </div>
  );
}