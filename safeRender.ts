/**
 * Güvenilmeyen backend verilerini güvenli şekilde render etmek için
 * savunmacı yardımcı fonksiyonlar.
 *
 * React zaten JSX içine yerleştirilen tüm string değerleri escape eder;
 * bu yüzden burada asıl amaç verilerin yanlışlıkla bir HTML sink içine
 * yönlendirilmesini engellemektir.
 *
 * Bilerek bir "html" helper fonksiyonu sunmuyoruz — güvenli varsayılanlarla
 * bunu sağlamak mümkün değildir ve bu kod tabanında
 * `dangerouslySetInnerHTML` kullanımı yasaktır.
 */

const MAX_DISPLAY_LEN = 4000;

// Görünmez ama metni gizleyebilen/yeniden sıralayabilen karakterler: kontrol
// karakterleri (C0 — sekme ve satır sonu hariç —, DEL, C1), bidi yön
// işaretleri/override'ları, sıfır genişlikli karakterler, satır/paragraf
// ayırıcıları ve Unicode tag karakterleri. Kod noktası olarak tutulur.
const INVISIBLE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x0008],
  [0x000b, 0x001f],
  [0x007f, 0x009f],
  [0x00ad, 0x00ad],
  [0x061c, 0x061c],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x206f],
  [0xfeff, 0xfeff],
  [0xfff9, 0xfffb],
  [0xe0000, 0xe007f],
];

function isInvisible(codePoint: number): boolean {
  return INVISIBLE_RANGES.some(
    ([low, high]) => codePoint >= low && codePoint <= high,
  );
}

/**
 * Güvenilmeyen metindeki görünmez karakterleri `[U+202E]` gibi görünür
 * işaretlere çevirir; böylece örneğin bir bidi override bir IOC'yi ekranda
 * farklı okutamaz. Diğer karakterler aynen kalır. Yalnızca gösterim içindir —
 * kopyalanan/indirilen değer ham kalmalıdır.
 */
export function revealInvisible(text: string): string {
  let out = "";
  for (const ch of text) {
    const codePoint = ch.codePointAt(0) ?? 0;
    out += isInvisible(codePoint)
      ? `[U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}]`
      : ch;
  }
  return out;
}

/**
 * Herhangi bir değeri düz metin ve uzunluğu sınırlandırılmış bir gösterim
 * string’ine dönüştürür (görünmez karakterler görünür işaretlere çevrilir).
 *
 * Dönen değer her zaman string türündedir ve JSX içine güvenle yerleştirilebilir
 * (React bunu escape eder).
 *
 * Bu değer HTML DEĞİLDİR ve hiçbir zaman bir HTML sink içine verilmemelidir.
 */
export function toDisplayString(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }

  let str: string;

  if (typeof value === "string") {
    str = value;
  } else if (
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    str = String(value);
  } else {
    try {
      str = JSON.stringify(value);
    } catch {
      str = "[serileştirilemeyen değer]";
    }
  }

  str = revealInvisible(str);

  if (str.length > MAX_DISPLAY_LEN) {
    return `${str.slice(0, MAX_DISPLAY_LEN - 1)}…`;
  }

  return str;
}

export interface SummaryEntry {
  key: string;
  value: string;
  /** Provider alanı döndürdü ama değer bildirmedi (`null`): false/0 değildir. */
  unknown?: true;
}

/**
 * `data_summary` nesnesini tablo gösterimi için anahtar/değer çiftlerine
 * dönüştürür. `null` değer "bilinmiyor" olarak işaretlenir (`unknown`), böylece
 * `false` / `0` gibi gerçek değerlerle karışmaz; hiç gelmeyen alan listelenmez.
 *
 * İç içe geçmiş yapılar JSON string olarak serileştirilir — hiçbir zaman
 * markup olarak render edilmez.
 */
export function summaryEntries(
  summary: Record<string, unknown> | undefined | null,
): SummaryEntry[] {
  if (!summary || typeof summary !== "object") {
    return [];
  }

  return Object.entries(summary).map(([key, value]): SummaryEntry =>
    value === null || value === undefined
      ? { key, value: "—", unknown: true }
      : { key, value: toDisplayString(value) },
  );
}

/**
 * JSON verisini bir <pre> bloğu için okunabilir şekilde formatlar.
 *
 * Düz metin string döndürür; React render sırasında bunu escape ettiği için
 * gömülü `<script>` vb. içerikler etkisiz düz metin olarak kalır.
 */
export function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}