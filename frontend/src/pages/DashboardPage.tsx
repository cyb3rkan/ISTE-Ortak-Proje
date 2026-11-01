import { Link } from "react-router";

import { Card } from "@/components/common/Card";
import { ErrorState } from "@/components/common/ErrorState";
import { SkeletonBar } from "@/components/common/LoadingState";
import { StatusBadge } from "@/components/layout/StatusBadge";
import { useHealth } from "@/hooks/useHealth";

const QUICK_ACTIONS = [
  {
    to: "/analyze",
    title: "Tekli IOC analizi",
    description: "Tek bir indicator için tüm provider'lar üzerinden enrichment yapın.",
  },
  {
    to: "/analyze/batch",
    title: "Toplu analiz",
    description: "Aynı anda 50 adede kadar indicator için enrichment yapın.",
  },
  {
    to: "/providers",
    title: "Provider durumu",
    description: "Hangi threat-intel provider'larının yapılandırıldığını kontrol edin.",
  },
  {
    to: "/cache",
    title: "Cache istatistikleri",
    description: "Enrichment cache istatistiklerini inceleyin.",
  },
];

const SECURITY_NOTES = [
  "Frontend bundle içinde hiçbir API key saklanmaz.",
  "Local demo için Auth devre dışı bırakılmış olarak varsayılır.",
  "Public deployment için gerçek kullanıcı doğrulaması gereklidir.",
];

export function DashboardPage() {
  const { data, error, loading, reload } = useHealth();

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold text-slate-100">
          IOC Enricher Kontrol Paneli
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Threat intelligence provider'larını kullanarak IP, domain, URL,
          hash ve email analizleri gerçekleştirin.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card title="Backend Sağlığı">
          {loading ? (
            <SkeletonBar className="h-6 w-32" />
          ) : error ? (
            <ErrorState message={error} onRetry={reload} />
          ) : data ? (
            <div className="space-y-2">
              <StatusBadge tone="ok" label={`Çevrimiçi · v${data.version}`} />
              <p className="text-sm text-slate-400">
                Servis:{" "}
                <span className="text-slate-200">{data.service}</span>
              </p>
            </div>
          ) : null}
        </Card>

        <Card title="Yapılandırılmış Provider'lar">
          {loading ? (
            <SkeletonBar className="h-8 w-16" />
          ) : (
            <p className="font-mono text-3xl font-bold text-slate-100">
              {data?.providers_configured ?? "—"}
            </p>
          )}
          <Link
            to="/providers"
            className="mt-2 inline-block text-xs text-accent hover:underline"
          >
            Provider'ları görüntüle →
          </Link>
        </Card>

        <Card title="AI Katmanı">
          {loading ? (
            <SkeletonBar className="h-6 w-24" />
          ) : (
            <StatusBadge
              tone={data?.ai_enabled ? "ok" : "neutral"}
              label={data?.ai_enabled ? "AI etkin" : "AI devre dışı"}
            />
          )}
        </Card>
      </div>

      <Card title="Hızlı İşlemler">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {QUICK_ACTIONS.map((action) => (
            <Link
              key={action.to}
              to={action.to}
              className="rounded-md border border-surface-border bg-surface p-3 transition-colors hover:border-accent/50"
            >
              <p className="text-sm font-medium text-slate-200">
                {action.title}
              </p>
              <p className="mt-0.5 text-xs text-slate-500">
                {action.description}
              </p>
            </Link>
          ))}
        </div>
      </Card>

      <Card title="Güvenlik Durumu">
        <ul className="space-y-1.5">
          {SECURITY_NOTES.map((note, i) => (
            <li key={i} className="flex gap-2 text-sm text-slate-400">
              <span className="text-accent" aria-hidden>
                ✓
              </span>
              <span>{note}</span>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}