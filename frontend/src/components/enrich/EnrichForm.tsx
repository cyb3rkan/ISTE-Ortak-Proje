import { useState } from "react";

import { IOC_TYPES } from "@/types/api";
import type { EnrichRequest, IocType } from "@/types/api";

const MAX_IOC_LEN = 2048;

type ReportFormat = NonNullable<EnrichRequest["save_report_format"]>;

const REPORT_OPTIONS: ReadonlyArray<{ value: ReportFormat | ""; label: string }> = [
  { value: "", label: "Kaydetme" },
  { value: "json", label: "JSON" },
  { value: "markdown", label: "Markdown" },
];

interface EnrichFormProps {
  onSubmit: (payload: EnrichRequest) => void;
  submitting: boolean;
}

/** Client-side korumaları içeren tekli IOC analiz formu. */
export function EnrichForm({ onSubmit, submitting }: EnrichFormProps) {
  const [ioc, setIoc] = useState("");
  const [iocType, setIocType] = useState<IocType>("auto");
  const [useCache, setUseCache] = useState(true);
  const [reportFormat, setReportFormat] = useState<ReportFormat | "">("");
  const [validationError, setValidationError] = useState<string | null>(null);

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    const trimmed = ioc.trim();
    if (!trimmed) {
      setValidationError("Lütfen bir IOC değeri girin.");
      return;
    }
    if (trimmed.length > MAX_IOC_LEN) {
      setValidationError(`IOC en fazla ${MAX_IOC_LEN} karakter olabilir.`);
      return;
    }
    setValidationError(null);
    onSubmit({
      ioc: trimmed,
      ioc_type: iocType,
      use_cache: useCache,
      // Only sent when chosen, so the default request is unchanged.
      ...(reportFormat ? { save_report_format: reportFormat } : {}),
    });
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4" noValidate>
      <div>
          <label
            htmlFor="ioc-input"
            className="mb-1 block text-xs font-medium text-slate-400"
          >
            Zararlı Gösterge (IOC)
          </label>
        <input
          id="ioc-input"
          name="ioc"
          type="text"
          value={ioc}
          onChange={(e) => setIoc(e.target.value)}
          maxLength={MAX_IOC_LEN}
          placeholder="8.8.8.8 · evil.example.com · https://… · hash · user@host"
          autoComplete="off"
          spellCheck={false}
          data-testid="enrich-ioc"
          className="w-full rounded-md border border-surface-border bg-surface px-3 py-2 font-mono text-sm text-slate-100 outline-hidden focus:border-accent/60"
        />
      </div>

      <div className="flex flex-wrap items-end gap-4">
        <div>
          <label
            htmlFor="ioc-type"
            className="mb-1 block text-xs font-medium text-slate-400"
          >
            Tür
          </label>
          <select
            id="ioc-type"
            value={iocType}
            onChange={(e) => setIocType(e.target.value as IocType)}
            data-testid="enrich-ioc-type"
            className="rounded-md border border-surface-border bg-surface px-3 py-2 text-sm text-slate-100 outline-hidden focus:border-accent/60"
          >
            {IOC_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label
            htmlFor="report-format"
            className="mb-1 block text-xs font-medium text-slate-400"
          >
            Rapor kaydet
          </label>
          <select
            id="report-format"
            value={reportFormat}
            onChange={(e) => setReportFormat(e.target.value as ReportFormat | "")}
            data-testid="enrich-report-format"
            className="rounded-md border border-surface-border bg-surface px-3 py-2 text-sm text-slate-100 outline-hidden focus:border-accent/60"
          >
            {REPORT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>

        <label className="flex items-center gap-2 pb-2 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={useCache}
            onChange={(e) => setUseCache(e.target.checked)}
            className="h-4 w-4 rounded-sm border-surface-border bg-surface accent-accent"
          />
          Cache kullan
        </label>

        <button
          type="submit"
          disabled={submitting}
          data-testid="enrich-submit"
          className="ml-auto rounded-md bg-accent px-4 py-2 text-sm font-semibold text-surface transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? "Analiz ediliyor…" : "Analiz Et"}
        </button>
      </div>

      {validationError ? (
        <p role="alert" className="text-sm text-risk-critical">
          {validationError}
        </p>
      ) : null}
    </form>
  );
}