/**
 * Toplu IOC girdisi ayrıştırma ve istemci tarafı doğrulama yardımcıları.
 *
 * Bağımlılıksız ve yan etkisiz tutulmuştur; böylece izole şekilde unit test
 * edilebilir. Backend tüm verileri tekrar doğrular (maksimum 50 kayıt,
 * uzunluk sınırları, tekrar eden kayıtların kaldırılması vb.) — bu katman
 * yalnızca kullanıcıya hızlı ve anlaşılır geri bildirim sağlar.
 */

export const MAX_BATCH_SIZE = 50;
export const MAX_IOC_LEN = 2048;
// Backend tarafındaki _MAX_BATCH_TOTAL_CHARS sınırı ile eşleşir.
export const MAX_BATCH_TOTAL_CHARS = MAX_IOC_LEN * MAX_BATCH_SIZE;

export interface ParsedBatch {
  /** Tekrar edenler kaldırılmış, kırpılmış ve sırası korunmuş IOC listesi. */
  iocs: string[];
  /** Kaldırılan tekrar eden satır sayısı. */
  duplicatesRemoved: number;
  /** Tekrar kaldırılmadan önceki boş olmayan satır sayısı. */
  rawCount: number;
}

/**
 * Textarea içeriğini temiz bir IOC listesine dönüştürür.
 * Boş / yalnızca boşluk içeren satırlar atılır; tekrar eden kayıtlar kaldırılır.
 */
export function parseBatchInput(raw: string): ParsedBatch {
  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  const seen = new Set<string>();
  const iocs: string[] = [];
  for (const line of lines) {
    if (!seen.has(line)) {
      seen.add(line);
      iocs.push(line);
    }
  }

  return {
    iocs,
    duplicatesRemoved: lines.length - iocs.length,
    rawCount: lines.length,
  };
}

/**
 * Ayrıştırılmış toplu veriyi doğrular.
 * Geçerliyse null, hata varsa kullanıcı dostu hata mesajı döner.
 */
export function validateBatch(parsed: ParsedBatch): string | null {
  if (parsed.iocs.length === 0) {
    return "En az bir IOC girin (her satıra bir IOC).";
  }

  if (parsed.iocs.length > MAX_BATCH_SIZE) {
    return `Çok fazla IOC girdiniz: ${parsed.iocs.length}. Maksimum sınır ${MAX_BATCH_SIZE}.`;
  }

  const tooLong = parsed.iocs.find((ioc) => ioc.length > MAX_IOC_LEN);

  if (tooLong) {
    return `IOC kayıtlarından biri ${MAX_IOC_LEN} karakter sınırını aşıyor.`;
  }

  const totalChars = parsed.iocs.reduce(
    (sum, ioc) => sum + ioc.length,
    0,
  );

  if (totalChars > MAX_BATCH_TOTAL_CHARS) {
    return "Toplu IOC girdisinin toplam boyutu çok büyük.";
  }

  return null;
}