interface ErrorStateProps {
  /** Önceden sanitize edilmiş mesaj (bkz: lib/api describeError). */
  message: string;
  requestId?: string | null;
  onRetry?: () => void;
}

export function ErrorState({ message, requestId, onRetry }: ErrorStateProps) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-risk-critical/40 bg-risk-critical/10 p-5"
    >
      <p className="text-sm font-medium text-risk-critical">
        Bir hata oluştu
      </p>
      {/* React bunu escape eder — backend hata string'leri düz metin olarak render edilir. */}
      <p className="mt-1 text-sm text-slate-300">{message}</p>
      {requestId ? (
        <p className="mt-2 font-mono text-xs text-slate-500">
          request_id: {requestId}
        </p>
      ) : null}
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="mt-3 rounded-md border border-surface-border bg-surface px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-accent/50"
        >
          Tekrar dene
        </button>
      ) : null}
    </div>
  );
}