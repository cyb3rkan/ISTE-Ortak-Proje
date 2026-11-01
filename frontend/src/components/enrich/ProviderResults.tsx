import { useId, useState } from "react";

import { Card } from "@/components/common/Card";
import { ProviderMetricChart } from "@/components/report/ProviderMetricCharts";
import type { ReportAudience } from "@/components/report/reportAudience";
import {
  FIELD_LABELS,
  TIME_FIELDS,
  analystProviderBrief,
  everydayOutcomeNote,
  everydayProviderFacts,
  formatTimestamp,
  providerId,
  providerStatusInfo,
} from "@/components/report/reportLanguage";
import type { ProviderOutcome } from "@/components/report/reportLanguage";
import { formatDuration } from "@/lib/format";
import { summaryEntries, toDisplayString } from "@/lib/safeRender";
import type { ProviderResultDTO } from "@/types/api";

// Provider erişilebilirliği tehdit değerlendirmesi değildir: hatalar risk
// paletinin "kritik" rengiyle değil, nötr/uyarı tonuyla gösterilir.

interface ProviderResultsProps {
  providers: ProviderResultDTO[];
  /** Varsayılan analist; günlük görünüm bunu açıkça `everyday` olarak verir. */
  audience?: ReportAudience;
  /** `RiskDTO.breakdown` — sağlayıcının skora sayısal katkısı (analist). */
  breakdown?: Record<string, number> | null;
}

const OUTCOME_ORDER: ReadonlyArray<{ outcome: ProviderOutcome; label: string; icon: string }> = [
  { outcome: "responded", label: "yanıt verdi", icon: "✓" },
  { outcome: "no_record", label: "kayıt bulamadı", icon: "○" },
  { outcome: "failed", label: "erişilemedi", icon: "!" },
  { outcome: "unsupported", label: "desteklenmiyor", icon: "–" },
  { outcome: "unknown", label: "durumu bilinmiyor", icon: "?" },
];

/** Sağlayıcıların kısa durum özeti — her durum ikon ve metinle. */
function CoverageStrip({ providers }: { providers: ProviderResultDTO[] }) {
  const counts = new Map<ProviderOutcome, number>();
  for (const p of providers) {
    const { outcome } = providerStatusInfo(p);
    counts.set(outcome, (counts.get(outcome) ?? 0) + 1);
  }
  const failed = counts.get("failed") ?? 0;
  const succeeded = (counts.get("responded") ?? 0) + (counts.get("no_record") ?? 0);

  return (
    <div className="mb-4 space-y-2" data-testid="provider-coverage-strip">
      <ul className="flex flex-wrap gap-2" aria-label="Sağlayıcı durum özeti">
        {OUTCOME_ORDER.filter(({ outcome }) => counts.has(outcome)).map(
          ({ outcome, label, icon }) => (
            <li
              key={outcome}
              className="rounded-md border border-surface-border bg-surface px-2.5 py-1 text-xs text-slate-300"
            >
              <span aria-hidden className="mr-1">
                {icon}
              </span>
              <span className="font-semibold text-slate-100">{counts.get(outcome)}</span> {label}
            </li>
          ),
        )}
      </ul>
      {failed > 0 && succeeded > 0 ? (
        <p className="text-xs text-slate-400">
          Erişilemeyen sağlayıcılar yalnızca kendi sonuçlarını etkiler; yanıt veren
          sağlayıcıların bulguları geçerliliğini korur.
        </p>
      ) : null}
    </div>
  );
}

function AnalystOutcomeNote({ outcome }: { outcome: ProviderOutcome }) {
  if (outcome === "failed") {
    return (
      <p className="mt-1 text-xs text-slate-400">
        <span className="font-medium text-risk-medium">Erişilemedi</span>
        {" — "}bu provider değerlendirmeye katılmadı; erişim/kota hatası risk skorunu
        etkilemez. Sonucu bilinmiyor — temiz kabul edilmemeli.
      </p>
    );
  }
  if (outcome === "no_record") {
    return (
      <p className="mt-1 text-xs text-slate-400">
        Provider yanıt verdi ama bu IOC için kaydı yok; kanıt yokluğu IOC'nin temiz olduğu
        anlamına gelmez.
      </p>
    );
  }
  if (outcome === "unsupported") {
    return (
      <p className="mt-1 text-xs text-slate-400">Bu provider bu IOC türü için sorgulanmadı.</p>
    );
  }
  return null;
}

function AnalystDetails({ provider }: { provider: ProviderResultDTO }) {
  const entries = summaryEntries(provider.data_summary);
  return (
    <div className="space-y-3">
      <ProviderMetricChart
        providerKey={providerId(provider.name)}
        summary={provider.data_summary ?? {}}
      />

      {entries.length > 0 ? (
        <dl className="grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-2">
          {entries.map(({ key, value, unknown }) => {
            const when = TIME_FIELDS.has(key) ? formatTimestamp(provider.data_summary[key]) : null;
            return (
              <div key={key} className="min-w-0 text-xs">
                <div className="flex justify-between gap-2">
                  <dt className="font-mono text-slate-500">{key}</dt>
                  {unknown ? (
                    // null: provider alanı bildirmedi — false/0 ile karıştırılmaz.
                    <dd
                      className="font-mono text-slate-500"
                      title="Bilinmiyor — provider bu alanın değerini bildirmedi"
                      aria-label="bilinmiyor"
                    >
                      {value}
                    </dd>
                  ) : (
                    <dd className="truncate font-mono text-slate-300" title={value}>
                      {value}
                    </dd>
                  )}
                </div>
                {FIELD_LABELS[key] || when ? (
                  <p className="text-[11px] text-slate-500">
                    {FIELD_LABELS[key] ?? ""}
                    {when ? `${FIELD_LABELS[key] ? " · " : ""}${when}` : ""}
                  </p>
                ) : null}
              </div>
            );
          })}
        </dl>
      ) : (
        <p className="text-xs text-slate-500">Bu provider özet alanı döndürmedi.</p>
      )}

      <dl className="space-y-1 border-t border-surface-border pt-2 text-xs">
        <div className="flex justify-between gap-2">
          <dt className="text-slate-500">Kaynak</dt>
          <dd className="text-slate-300">{provider.name}</dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-slate-500">Ham durum</dt>
          <dd className="font-mono text-slate-300">{provider.status}</dd>
        </div>
        {provider.response_time_ms != null ? (
          <div className="flex justify-between gap-2">
            <dt className="text-slate-500">Yanıt süresi</dt>
            <dd className="font-mono text-slate-300">
              {formatDuration(provider.response_time_ms)}
            </dd>
          </div>
        ) : null}
      </dl>

      {provider.error ? (
        // Backend bu string'i zaten sanitize eder; React render sırasında escape eder.
        <p className="wrap-break-word text-xs text-slate-400">
          <span className="text-slate-500">Hata mesajı: </span>
          {toDisplayString(provider.error)}
        </p>
      ) : null}
    </div>
  );
}

function EverydayDetails({
  provider,
  outcome,
}: {
  provider: ProviderResultDTO;
  outcome: ProviderOutcome;
}) {
  const facts = outcome === "responded" ? everydayProviderFacts(provider) : [];
  return (
    <div className="space-y-3">
      {outcome === "responded" ? (
        <ProviderMetricChart
          providerKey={providerId(provider.name)}
          summary={provider.data_summary ?? {}}
        />
      ) : null}
      {facts.length > 0 ? (
        <ul className="space-y-1">
          {facts.map((fact, i) => (
            <li key={i} className="flex gap-2 text-sm text-slate-300">
              <span aria-hidden className="text-accent">
                ▸
              </span>
              <span className="wrap-break-word">{toDisplayString(fact)}</span>
            </li>
          ))}
        </ul>
      ) : outcome === "responded" ? (
        <p className="text-sm text-slate-400">
          Bu kaynak, sade bir özet çıkarılabilecek bilgi döndürmedi.
        </p>
      ) : null}
      <p className="text-xs text-slate-400">{everydayOutcomeNote(outcome)}</p>
    </div>
  );
}

function ProviderCard({
  provider,
  audience,
  contribution,
}: {
  provider: ProviderResultDTO;
  audience: ReportAudience;
  contribution: number | null;
}) {
  const [open, setOpen] = useState(false);
  const detailsId = useId();
  const info = providerStatusInfo(provider);
  const analyst = audience === "analyst";
  const brief = analyst
    ? analystProviderBrief(provider)
    : info.outcome === "responded"
      ? (everydayProviderFacts(provider)[0] ?? null)
      : null;

  return (
    <li
      className="rounded-md border border-surface-border bg-surface p-3"
      data-testid="provider-card"
      data-provider-status={provider.status}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-medium text-slate-200">{provider.name}</h3>
        <span className={`text-xs font-medium ${info.tone}`}>
          <span aria-hidden className="mr-1">
            {info.icon}
          </span>
          {info.label}
        </span>
      </div>

      <p className="mt-1 text-xs text-slate-400">
        {info.participation}
        {analyst && contribution != null && info.outcome === "responded"
          ? ` · skora katkı ${Math.round(contribution)} puan`
          : ""}
      </p>

      {brief ? (
        <p
          className={`mt-1 wrap-break-word text-xs ${
            analyst ? "font-mono text-slate-300" : "text-slate-300"
          }`}
        >
          {toDisplayString(brief)}
        </p>
      ) : null}

      {analyst ? (
        <AnalystOutcomeNote outcome={info.outcome} />
      ) : info.outcome !== "responded" ? (
        <p className="mt-1 text-xs text-slate-400">{everydayOutcomeNote(info.outcome)}</p>
      ) : null}

      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls={detailsId}
        className="mt-2 rounded-sm text-xs font-medium text-accent hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
      >
        {open ? "Detayları gizle" : "Detayları göster"}
        <span className="sr-only"> — {provider.name}</span>
      </button>

      {open ? (
        <div id={detailsId} className="mt-3 border-t border-surface-border pt-3">
          {analyst ? (
            <AnalystDetails provider={provider} />
          ) : (
            <EverydayDetails provider={provider} outcome={info.outcome} />
          )}
        </div>
      ) : null}
    </li>
  );
}

export function ProviderResults({
  providers,
  audience = "analyst",
  breakdown = null,
}: ProviderResultsProps) {
  const analyst = audience === "analyst";
  return (
    <Card title={`${analyst ? "Provider sonuçları" : "Kaynak sonuçları"} (${providers.length})`}>
      {providers.length === 0 ? (
        <p className="text-sm text-slate-500">
          {analyst
            ? "Hiçbir provider yanıt vermedi. Backend tarafında provider API key'leri yapılandırılmamış olabilir."
            : "Bu analizde hiçbir kaynaktan sonuç alınamadı."}
        </p>
      ) : (
        <>
          <CoverageStrip providers={providers} />
          <ul className="grid grid-cols-1 gap-2 lg:grid-cols-2">
            {providers.map((p, i) => {
              const id = providerId(p.name);
              const points = id && breakdown ? breakdown[id] : undefined;
              return (
                <ProviderCard
                  key={`${p.name}-${i}`}
                  provider={p}
                  audience={audience}
                  contribution={typeof points === "number" && Number.isFinite(points) ? points : null}
                />
              );
            })}
          </ul>
        </>
      )}
    </Card>
  );
}
