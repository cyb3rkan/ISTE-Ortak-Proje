import type { HTMLAttributes, Ref } from "react";

interface DemoTextFieldProps {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: "text" | "email" | "password";
  autoComplete?: string;
  inputMode?: HTMLAttributes<HTMLInputElement>["inputMode"];
  maxLength?: number;
  error?: string | null;
  /** Hata dışında alanı açıklayan öğelerin id'leri (ör. gereksinim listesi). */
  describedBy?: string;
  inputRef?: Ref<HTMLInputElement>;
  className?: string;
}

/**
 * Görünür etiketli, erişilebilir hata mesajlı form alanı.
 * Hata metni `aria-describedby` ile alana bağlanır; değer hiçbir zaman
 * hata metnine eklenmez.
 */
export function DemoTextField({
  id,
  label,
  value,
  onChange,
  type = "text",
  autoComplete,
  inputMode,
  maxLength,
  error,
  describedBy,
  inputRef,
  className = "",
}: DemoTextFieldProps) {
  const errorId = `${id}-error`;
  const describedByIds = [error ? errorId : null, describedBy].filter(Boolean).join(" ");

  return (
    <div className={className}>
      <label htmlFor={id} className="text-xs font-medium text-slate-400">
        {label}
      </label>
      <input
        id={id}
        ref={inputRef}
        name={id}
        type={type}
        autoComplete={autoComplete}
        inputMode={inputMode}
        maxLength={maxLength}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedByIds || undefined}
        className={`mt-1 w-full rounded-md border bg-surface px-3 py-2 text-sm text-slate-100 focus:outline-hidden focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-accent ${
          error ? "border-risk-critical/70" : "border-surface-border focus:border-accent"
        }`}
      />
      {error ? (
        <p id={errorId} className="mt-1 text-xs text-risk-critical">
          {error}
        </p>
      ) : null}
    </div>
  );
}
