import { useState } from "react";

interface CopyButtonProps {
  /** Kopyalanacak düz metin. Asla HTML değil. */
  value: string;
  label?: string;
}

/**
 * Panoya kopyalama butonu.
 *
 * Pano yazma işlemi yalnızca kullanıcının tıklaması sonucu gerçekleşir —
 * asla otomatik değil. Async Clipboard API kullanılır ve tarayıcı erişimi
 * reddederse (ör. güvenli olmayan context) sessizce başarısız olur.
 */
export function CopyButton({ value, label = "Kopyala" }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard kullanılamıyor — sessizce yok sayılır, UI bozulmaz.
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="rounded-sm border border-surface-border bg-surface px-2 py-1 text-xs text-slate-300 hover:border-accent/50"
    >
      {copied ? "Kopyalandı" : label}
    </button>
  );
}