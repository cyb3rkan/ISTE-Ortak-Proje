import { StatusBadge } from "@/components/layout/StatusBadge";
import type { ProviderStatusDTO } from "@/types/api";

function ProviderCard({ provider }: { provider: ProviderStatusDTO }) {
  return (
    <div className="rounded-lg border border-surface-border bg-surface-raised p-4">
      <div className="flex items-start justify-between gap-2">
        <span className="font-medium text-slate-200">{provider.name}</span>
        <span className="font-mono text-xs uppercase text-slate-500">
          {provider.status}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <span
          data-testid={
            provider.configured ? "badge-configured" : "badge-no-api-key"
          }
        >
          <StatusBadge
            tone={provider.configured ? "ok" : "neutral"}
            label={provider.configured ? "Yapılandırıldı" : "API key yok"}
          />
        </span>
        <span
          data-testid={
            provider.enabled ? "badge-enabled" : "badge-disabled"
          }
        >
          <StatusBadge
            tone={provider.enabled ? "ok" : "neutral"}
            label={provider.enabled ? "Aktif" : "Devre dışı"}
          />
        </span>
      </div>
      {provider.last_error ? (
        // Server-side sanitize edilir; React bunu escape eder — asla HTML olarak render edilmez.
        <p className="mt-3 text-xs text-risk-critical">
          {provider.last_error}
        </p>
      ) : null}
    </div>
  );
}

export function ProviderStatusGrid({
  providers,
}: {
  providers: ProviderStatusDTO[];
}) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {providers.map((p) => (
        <ProviderCard key={p.name} provider={p} />
      ))}
    </div>
  );
}