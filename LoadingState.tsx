export function LoadingState({ label = "Yükleniyor…" }: { label?: string }) {
  return (
    <div
      role="status"
      className="flex items-center gap-3 rounded-lg border border-surface-border bg-surface-raised p-6 text-slate-400"
    >
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-accent border-t-transparent" />
      <span className="text-sm">{label}</span>
    </div>
  );
}

/** Satır içi skeleton bar — bir bölüm yüklenirken kart içinde kullanılır. */
export function SkeletonBar({ className = "" }: { className?: string }) {
  return (
    <div
      className={`animate-pulse rounded-sm bg-slate-700/40 ${className}`}
      aria-hidden
    />
  );
}