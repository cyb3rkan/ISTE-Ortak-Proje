/**
 * Çalışma zamanı yapılandırması.
 *
 * Frontend’in okuduğu TEK ortam değişkenleri backend temel URL’si ve gizli
 * olmayan UI kimlik doğrulama modu bayrağıdır. API anahtarı, admin anahtarı
 * veya token gibi gizli bilgiler ASLA frontend tarafından okunmaz —
 * `VITE_` ile başlayan tüm değişkenler public bundle içine girer ve gizli
 * veri içermemelidir.
 *
 * `VITE_AUTH_MODE`:
 *   - "disabled" (varsayılan) — yerel demo modu; rotalar herkese açıktır,
 *     giriş ekranı gösterilmez.
 *   - "jwt" — giriş ekranını gösterir ve korumalı rotaları aktif eder.
 *
 * Bu ayar yalnızca UI davranışını değiştirir; bir güvenlik kontrolü değildir.
 * Gerçek yetkilendirme backend tarafından zorunlu olarak uygulanır.
 *
 * `VITE_PROTOTYPE_MODE`:
 *   - kapalı (varsayılan) — `/demo` rotaları tanımlanmaz, 404'e düşer.
 *   - "true" veya "1" — çok kullanıcılı arayüz prototipini `/demo` altında
 *     açar. Demo alanı tamamen mock'tur; backend'e istek atmaz ve
 *     `VITE_AUTH_MODE` / gerçek JWT oturumundan bağımsızdır.
 */

const DEFAULT_BASE_URL = "http://127.0.0.1:8000";

function normalizeBaseUrl(raw: string | undefined): string {
  const trimmed = (raw ?? "").trim();

  // Açıkça boş değer verilirse "relative /api URL" kullan anlamına gelir.
  // Docker / nginx dağıtımında frontend ve backend aynı origin üzerinden
  // çalışır ve /api proxy edilir; bu nedenle cross-origin base URL gerekmez.
  // Varsayılan localhost adresine yalnızca değişken tamamen tanımsızsa düşülür.
  if (raw !== undefined && trimmed === "") {
    return "";
  }

  const value = trimmed || DEFAULT_BASE_URL;

  // Sondaki "/" karakterlerini kaldırır; böylece çağıran kod güvenli şekilde
  // `/api/v1/...` ekleyebilir.
  return value.replace(/\/+$/, "");
}

export type AuthMode = "disabled" | "jwt";

function normalizeAuthMode(raw: string | undefined): AuthMode {
  return (raw ?? "").trim().toLowerCase() === "jwt"
    ? "jwt"
    : "disabled";
}

function normalizeFlag(raw: string | undefined): boolean {
  const value = (raw ?? "").trim().toLowerCase();
  return value === "true" || value === "1";
}

export const config = {
  apiBaseUrl: normalizeBaseUrl(import.meta.env.VITE_API_BASE_URL),
  apiPrefix: "/api/v1",
  requestTimeoutMs: 30_000,
  authMode: normalizeAuthMode(import.meta.env.VITE_AUTH_MODE),
  prototypeMode: normalizeFlag(import.meta.env.VITE_PROTOTYPE_MODE),
} as const;

export function apiUrl(path: string): string {
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return `${config.apiBaseUrl}${config.apiPrefix}${suffix}`;
}