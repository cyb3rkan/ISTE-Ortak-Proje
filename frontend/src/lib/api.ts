/**
 * IOC Enricher backend'i için typed API client.
 *
 * Tasarım notları:
 *  - Browser `fetch` API'sini kullanır; ekstra HTTP dependency içermez.
 *  - Tüm request'ler `AbortController` timeout'u ile sınırlandırılmıştır.
 *  - Non-2xx response'lar mümkünse RFC 7807 problem+json olarak parse edilir
 *    ve typed `ApiError` olarak yeniden fırlatılır. Eğer body HTML/plain text
 *    ise (örn. proxy 502 sayfası), generic ve güvenli bir mesaj döndürülür —
 *    ham response body asla UI'a gösterilmez.
 *
 * Auth:
 *  - Browser tarafında ASLA API-key / admin-key header'ı gönderilmez —
 *    frontend hiçbir zaman API key tutmaz.
 *  - In-memory access token mevcutsa şu şekilde gönderilir:
 *    `Authorization: Bearer <token>`.
 *    Token yalnızca memory içinde tutulur (`auth/tokenStore`) —
 *    localStorage/sessionStorage kullanılmaz.
 *  - 401 durumunda client tek seferlik refresh attempt yapar
 *    (httpOnly refresh cookie kullanılarak) ve orijinal request'i bir kez
 *    yeniden dener. Refresh başarısız olursa session anonymous moda düşer.
 *  - `credentials: "include"` kullanılır; böylece refresh cookie round-trip yapabilir.
 */

import { getAccessToken, tryRefreshAccessToken } from "@/auth/tokenStore";
import { apiUrl, config } from "./config";

import type {
  BatchEnrichRequest,
  BatchEnrichResponse,
  CacheStatsDTO,
  EnrichRequest,
  EnrichmentDTO,
  HealthResponse,
  ProblemDetails,
  ProviderStatusResponse,
  ReportResponse,
} from "@/types/api";

export class ApiError extends Error {
  readonly status: number;
  readonly problem: ProblemDetails | null;
  readonly requestId: string | null;

  constructor(message: string, status: number, problem: ProblemDetails | null) {
    super(message);

    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
    this.requestId = problem?.request_id ?? null;
  }
}

/** HTTP status üretmeyen timeout / network hatası. */
export class NetworkError extends Error {
  constructor(message: string) {
    super(message);

    this.name = "NetworkError";
  }
}

function isProblemDetails(value: unknown): value is ProblemDetails {
  return (
    !!value &&
    typeof value === "object" &&
    typeof (value as Record<string, unknown>).title === "string" &&
    typeof (value as Record<string, unknown>).status === "number"
  );
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
}

/** Timeout + abort desteği ile tek bir fiziksel fetch işlemi. */
async function performFetch(
  path: string,
  opts: RequestOptions,
): Promise<Response> {
  const controller = new AbortController();

  const timeout = setTimeout(
    () => controller.abort(),
    config.requestTimeoutMs,
  );

  // Caller kendi signal'ını gönderdiyse bizim controller'ı abort et.
  if (opts.signal) {
    if (opts.signal.aborted) {
      controller.abort();
    } else {
      opts.signal.addEventListener("abort", () => controller.abort());
    }
  }

  const accessToken = getAccessToken();

  try {
    return await fetch(apiUrl(path), {
      method: opts.method ?? "GET",

      // Refresh cookie gönderilsin ki 401 -> refresh cycle çalışabilsin.
      credentials: "include",

      headers: {
        Accept: "application/json",

        ...(opts.body !== undefined
          ? { "Content-Type": "application/json" }
          : {}),

        // Sadece Bearer token — browser tarafında API key asla kullanılmaz.
        ...(accessToken
          ? { Authorization: `Bearer ${accessToken}` }
          : {}),
      },

      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,

      signal: controller.signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new NetworkError(
        "İstek zaman aşımına uğradı. Backend'in çalıştığını kontrol edin.",
      );
    }

    throw new NetworkError(
      "Backend'e ulaşılamadı. API servisinin çalıştığını kontrol edin.",
    );
  } finally {
    clearTimeout(timeout);
  }
}

async function request<T>(
  path: string,
  opts: RequestOptions = {},
): Promise<T> {
  let response = await performFetch(path, opts);

  // Tek seferlik 401 recovery:
  // Token varsa (veya alınabiliyorsa) refresh dene, ardından request'i
  // yalnızca bir kez yeniden gönder.
  // Bu mekanizma sadece jwt auth mode'da anlamlıdır.
  if (response.status === 401 && config.authMode === "jwt") {
    const newToken = await tryRefreshAccessToken();

    if (newToken) {
      response = await performFetch(path, opts);
    }
  }

  const contentType = response.headers.get("content-type") ?? "";

  const isJson =
    contentType.includes("application/json") ||
    contentType.includes("application/problem+json");

  if (!response.ok) {
    let problem: ProblemDetails | null = null;

    if (isJson) {
      try {
        const parsed: unknown = await response.json();

        if (isProblemDetails(parsed)) {
          problem = parsed;
        }
      } catch {
        problem = null;
      }
    }

    // Ham HTML/text response asla UI'a gösterilmez.
    const message =
      problem?.detail ??
      problem?.title ??
      `İstek ${response.status} status kodu ile başarısız oldu.`;

    throw new ApiError(message, response.status, problem);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  if (!isJson) {
    throw new ApiError(
      "Backend beklenmeyen bir response (JSON olmayan) döndürdü.",
      response.status,
      null,
    );
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError(
      "Backend geçersiz/malformed JSON response döndürdü.",
      response.status,
      null,
    );
  }
}

// ---------------------------------------------------------------------------
// Public API surface
// ---------------------------------------------------------------------------

export function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request<HealthResponse>("/health", { signal });
}

export function enrichSingle(
  payload: EnrichRequest,
  signal?: AbortSignal,
): Promise<EnrichmentDTO> {
  return request<EnrichmentDTO>("/enrich", {
    method: "POST",
    body: payload,
    signal,
  });
}

export function enrichBatch(
  payload: BatchEnrichRequest,
  signal?: AbortSignal,
): Promise<BatchEnrichResponse> {
  return request<BatchEnrichResponse>("/enrich/batch", {
    method: "POST",
    body: payload,
    signal,
  });
}

export function getProviders(
  signal?: AbortSignal,
): Promise<ProviderStatusResponse> {
  return request<ProviderStatusResponse>("/providers", { signal });
}

export function getCacheStats(signal?: AbortSignal): Promise<CacheStatsDTO> {
  return request<CacheStatsDTO>("/cache", { signal });
}

export function getReport(
  reportId: string,
  signal?: AbortSignal,
): Promise<ReportResponse> {
  // ID path-segment olarak encode edilir.
  // Backend ayrıca UUID formatını validate eder,
  // böylece traversal attempt'leri server-side reddedilir.
  return request<ReportResponse>(
    `/reports/${encodeURIComponent(reportId)}`,
    { signal },
  );
}

/** Herhangi bir throw edilen değeri UI için güvenli ve okunabilir mesaja çevirir. */
export function describeError(err: unknown): string {
  if (err instanceof ApiError || err instanceof NetworkError) {
    return err.message;
  }

  if (err instanceof Error) {
    return "Beklenmeyen bir hata oluştu.";
  }

  return "Beklenmeyen bir hata oluştu.";
}