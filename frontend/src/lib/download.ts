/**
 * Düz metin içeriği için istemci tarafında dosya indirme işlemini tetikler.
 *
 * Blob + object URL + geçici anchor click yaklaşımı kullanılır. Bu işlem
 * yalnızca bir kullanıcı etkileşimi sonucunda çalışır
 * (çağıran taraf bunu bir onClick olayına bağlar).
 *
 * Hiçbir HTML üretilmez — içerik doğrudan Blob içine olduğu gibi yazılır.
 */

/** Güvenli olmayan karakterleri dosya adından temizler. */
export function safeFilename(base: string, extension: string): string {
  const cleanedBase =
    base.replace(/[^A-Za-z0-9._-]/g, "").slice(0, 80) || "rapor";

  const cleanedExt =
    extension.replace(/[^A-Za-z0-9]/g, "").slice(0, 8) || "txt";

  return `${cleanedBase}.${cleanedExt}`;
}

/** Rapor formatını uygun dosya uzantısına dönüştürür. */
export function extensionForFormat(format: string): string {
  const f = format.toLowerCase();

  if (f === "json") return "json";
  if (f === "markdown" || f === "md") return "md";

  return "txt";
}

export function downloadTextFile(
  filename: string,
  content: string,
  mimeType = "text/plain",
): void {
  const blob = new Blob([content], {
    type: `${mimeType};charset=utf-8`,
  });

  const url = URL.createObjectURL(blob);

  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;

  // Append → click → remove yaklaşımı farklı tarayıcılarda DOM'un temiz
  // kalmasını sağlar.
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);

  // İndirmenin başlayabilmesi için object URL bir sonraki event loop
  // turunda serbest bırakılır.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}