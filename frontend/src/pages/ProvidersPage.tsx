import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { LoadingState } from "@/components/common/LoadingState";
import { StatusBadge } from "@/components/layout/StatusBadge";
import { ProviderStatusGrid } from "@/components/providers/ProviderStatusGrid";
import { useProviders } from "@/hooks/useProviders";

export function ProvidersPage() {
  const { data, error, loading, reload } = useProviders();

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Provider'lar</h1>
          <p className="mt-1 text-sm text-slate-400">
            Threat intelligence provider yapılandırması ve çalışma durumu.
          </p>
        </div>
        {data ? (
          <StatusBadge
            tone={data.ai_enabled ? "ok" : "neutral"}
            label={data.ai_enabled ? "AI etkin" : "AI devre dışı"}
          />
        ) : null}
      </div>

      {loading ? <LoadingState label="Provider'lar yükleniyor…" /> : null}
      {error ? <ErrorState message={error} onRetry={reload} /> : null}
      {data && data.providers.length === 0 ? (
        <EmptyState title="Backend tarafından bildirilen provider bulunamadı." />
      ) : null}
      {data && data.providers.length > 0 ? (
        <ProviderStatusGrid providers={data.providers} />
      ) : null}
    </div>
  );
}