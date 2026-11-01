import { useMemo, useState } from "react";

import {
  MAX_BATCH_SIZE,
  parseBatchInput,
  validateBatch,
} from "@/lib/batch";
import { IOC_TYPES } from "@/types/api";
import type { BatchEnrichRequest, IocType } from "@/types/api";

interface BatchFormProps {
  onSubmit: (payload: BatchEnrichRequest) => void;
  submitting: boolean;
}

/** Canlı ayrıştırma geri bildirimli çoklu IOC analiz formu. */
export function BatchForm({ onSubmit, submitting }: BatchFormProps) {
  const [text, setText] = useState("");
  const [iocType, setIocType] = useState<IocType>("auto");
  const [useCache, setUseCache] = useState(true);
  const [validationError, setValidationError] = useState<string | null>(null);

  // Live parse so the user sees counts as they type.
  const parsed = useMemo(() => parseBatchInput(text), [text]);

  function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    const error = validateBatch(parsed);
    if (error) {
      setValidationError(error);
      return;
    }
    setValidationError(null);
    onSubmit({
      iocs: parsed.iocs,
      ioc_type: iocType,
      use_cache: useCache,
    });
  }

  const overLimit = parsed.iocs.length > MAX_BATCH_SIZE;

  return (
    <form onSubmit={handleSubmit} className="space-y-4" noValidate>
      <div>
        <label
          htmlFor="batch-input"
          className="mb-1 block text-xs font-medium text-slate-400"
        >
          IOC listesi — her satıra bir IOC (en fazla {MAX_BATCH_SIZE})
        </label>
        <textarea
          id="batch-input"
          name="iocs"
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={8}
          spellCheck={false}
          placeholder={"8.8.8.8\nevil.example.com\nhttps://malicious.example/payload"}
          className="w-full resize-y rounded-md border border-surface-border bg-surface px-3 py-2 font-mono text-sm text-slate-100 outline-hidden focus:border-accent/60"
        />
        <div className="mt-1 flex flex-wrap gap-4 text-xs text-slate-500">
          <span>
            Benzersiz IOC:{" "}
            <span
              className={
                overLimit ? "font-semibold text-risk-critical" : "text-slate-300"
              }
            >
              {parsed.iocs.length}
            </span>
          </span>
          {parsed.duplicatesRemoved > 0 ? (
            <span>
              Yok sayılan tekrar:{" "}
              <span className="text-risk-medium">
                {parsed.duplicatesRemoved}
              </span>
            </span>
          ) : null}
        </div>
      </div>

      <div className="flex flex-wrap items-end gap-4">
        <div>
          <label
            htmlFor="batch-ioc-type"
            className="mb-1 block text-xs font-medium text-slate-400"
          >
            Tür
          </label>
          <select
            id="batch-ioc-type"
            value={iocType}
            onChange={(e) => setIocType(e.target.value as IocType)}
            className="rounded-md border border-surface-border bg-surface px-3 py-2 text-sm text-slate-100 outline-hidden focus:border-accent/60"
          >
            {IOC_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
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
          data-testid="batch-submit"
          className="ml-auto rounded-md bg-accent px-4 py-2 text-sm font-semibold text-surface transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting
            ? "Analiz ediliyor…"
            : parsed.iocs.length
              ? `Analiz Et (${parsed.iocs.length} IOC)`
              : "Analiz Et"}
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
