/**
 * Erişilebilir onay penceresi (modal).
 *
 * - Açılınca güvenli seçenek olan "Vazgeç" odaklanır.
 * - Tab/Shift+Tab pencere içinde döner; Escape iptal eder.
 * - Kapanınca odak, pencereyi açan öğeye geri verilir.
 * - `document.body` altına portal ile render edilir.
 */

import { useEffect, useId, useRef } from "react";
import type { KeyboardEvent, ReactNode } from "react";
import { createPortal } from "react-dom";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  /** İşlem sürerken onay düğmesinde gösterilir. */
  busyLabel?: string;
  /** `danger`: yıkıcı işlem (kırmızı), `primary`: olağan işlem. */
  tone?: "danger" | "primary";
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  busyLabel = "Siliniyor…",
  tone = "danger",
  busy = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const titleId = useId();
  const descriptionId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement as HTMLElement | null;
    cancelRef.current?.focus();
    return () => opener?.focus();
  }, [open]);

  if (!open) return null;

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      if (!busy) onCancel();
      return;
    }
    if (event.key !== "Tab") return;
    const focusable = dialogRef.current?.querySelectorAll<HTMLElement>(
      "button:not(:disabled), a[href]",
    );
    if (!focusable || focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/60 p-4 sm:items-center">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        onKeyDown={handleKeyDown}
        className="w-full max-w-sm rounded-lg border border-surface-border bg-surface-raised shadow-xl"
      >
        <div className="px-5 py-4">
          <h2 id={titleId} className="text-sm font-semibold text-slate-100">
            {title}
          </h2>
          <div id={descriptionId} className="mt-2 text-xs text-slate-400">
            {children}
          </div>
        </div>
        <div className="flex flex-col-reverse gap-2 border-t border-surface-border px-5 py-3 sm:flex-row sm:justify-end">
          <button
            ref={cancelRef}
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="min-h-10 rounded-md border border-surface-border bg-surface px-4 py-2 text-sm font-medium text-slate-200 hover:border-accent/50 focus-visible:outline-2 focus-visible:outline-accent disabled:opacity-60"
          >
            Vazgeç
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className={`min-h-10 rounded-md px-4 py-2 text-sm font-semibold disabled:opacity-60 ${
              tone === "danger"
                ? "border border-risk-critical/60 bg-risk-critical/15 text-risk-critical hover:bg-risk-critical/25 focus-visible:outline-2 focus-visible:outline-risk-critical"
                : "bg-accent text-slate-900 hover:bg-accent/90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
            }`}
          >
            {busy ? busyLabel : confirmLabel}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
