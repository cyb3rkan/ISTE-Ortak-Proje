/**
 * Kullanıcıya ait sağlayıcı API anahtarları — demo servis sınırı.
 *
 * Ekranlar yalnızca o anki demo oturumuna bağlanmış `DemoApiKeyService`
 * örneğini görür (`DemoApiKeyStore.forOwner`); başka bir sahibin verisine
 * erişen bir yöntem yoktur. Backend entegrasyonunda sahiplik sunucu tarafında
 * oturumdaki kullanıcıdan belirlenmeli; endpoint sözleşmesi henüz yoktur.
 *
 * SECURITY:
 *  - Ham anahtar yalnızca `saveKey` çağrısında geçici girdi olarak alınır;
 *    saklanmaz, loglanmaz ve hiçbir sonuçta geri döndürülmez.
 *  - Bellekte yalnızca maskeleme metadata'sı tutulur: durum, son 4 karakter
 *    (kısa anahtarlarda hiç), güncellenme zamanı.
 *  - Mock hiçbir zaman sağlayıcıya bağlanmaz ve "verified" durumu ÜRETMEZ.
 */

import { DEMO_PROVIDERS } from "./demoProviders";
import type { ProviderId } from "./demoProviders";

export type ApiKeyStatus =
  | "not_configured"
  | "saved_unverified"
  | "verification_skipped"
  /** Yalnızca gerçek backend doğrulaması üretebilir; mock asla üretmez. */
  | "verified"
  | "invalid"
  | "permission_denied"
  | "rate_limited"
  | "provider_unreachable"
  | "unexpected_error";

export const API_KEY_ERROR_STATUSES: readonly ApiKeyStatus[] = [
  "invalid",
  "permission_denied",
  "rate_limited",
  "provider_unreachable",
  "unexpected_error",
];

export interface ApiKeyMetadata {
  providerId: ProviderId;
  status: ApiKeyStatus;
  /** Kayıtlı anahtarın son 4 karakteri; kısa anahtarlarda null. */
  last4: string | null;
  updatedAt: Date | null;
  /** Durum bir demo/mock tarafından üretildiyse true (gerçek sağlayıcı yanıtı değil). */
  simulated: boolean;
}

export type SaveApiKeyResult =
  | { ok: true; key: ApiKeyMetadata }
  | { ok: false; error: "invalid_input" | "unexpected_error" };

export type CheckApiKeyResult =
  | { ok: true; key: ApiKeyMetadata }
  | { ok: false; error: "not_configured" };

export type DeleteApiKeyResult = { ok: true; key: ApiKeyMetadata };

/** Tek bir sahibe (demo oturumuna) bağlı servis. */
export interface DemoApiKeyService {
  listKeys(): Promise<ApiKeyMetadata[]>;
  saveKey(providerId: ProviderId, rawKey: string): Promise<SaveApiKeyResult>;
  /** Demo: sağlayıcıya bağlanmaz; yalnızca seçili demo senaryosunu uygular. */
  checkKey(providerId: ProviderId): Promise<CheckApiKeyResult>;
  deleteKey(providerId: ProviderId): Promise<DeleteApiKeyResult>;
}

export interface DemoApiKeyStore {
  forOwner(ownerId: string): DemoApiKeyService;
  clearOwner(ownerId: string): void;
}

// --- Geliştirici demo paneli senaryoları ----------------------------------

export type VerificationScenario =
  | "not_verified"
  | "invalid"
  | "permission_denied"
  | "rate_limited"
  | "provider_unreachable"
  | "unexpected_error";

export interface ApiKeyScenarios {
  verify: VerificationScenario;
  save: "saved" | "unexpected_error";
}

export const DEFAULT_API_KEY_SCENARIOS: ApiKeyScenarios = {
  verify: "not_verified",
  save: "saved",
};

// --- Girdi doğrulama --------------------------------------------------------

export const API_KEY_MAX_LENGTH = 256;
/** Bu uzunluğun altındaki anahtarlarda son karakterler de gösterilmez. */
const LAST4_MIN_LENGTH = 12;

/** Hata metni hiçbir zaman girilen değeri içermez. */
export function validateApiKeyInput(raw: string): string | null {
  const value = raw.trim();
  if (!value) return "Anahtar gerekli. Sağlayıcı hesabınızdan kopyaladığınız anahtarı yapıştırın.";
  if (/\s/.test(value)) return "Anahtar boşluk içeremez. Kopyalarken fazladan karakter alınmış olabilir.";
  if (value.length > API_KEY_MAX_LENGTH) {
    return `Anahtar en fazla ${API_KEY_MAX_LENGTH} karakter olabilir.`;
  }
  return null;
}

// --- Mock uygulama --------------------------------------------------------

interface MockOptions {
  getScenarios: (providerId: ProviderId) => ApiKeyScenarios;
  delayMs?: number;
}

function wait(ms: number): Promise<void> {
  return ms > 0 ? new Promise((resolve) => setTimeout(resolve, ms)) : Promise.resolve();
}

function emptyMetadata(providerId: ProviderId): ApiKeyMetadata {
  return { providerId, status: "not_configured", last4: null, updatedAt: null, simulated: true };
}

const SCENARIO_STATUS: Record<VerificationScenario, ApiKeyStatus> = {
  not_verified: "verification_skipped",
  invalid: "invalid",
  permission_denied: "permission_denied",
  rate_limited: "rate_limited",
  provider_unreachable: "provider_unreachable",
  unexpected_error: "unexpected_error",
};

export function createMockApiKeyStore({ getScenarios, delayMs = 300 }: MockOptions): DemoApiKeyStore {
  // ownerId -> providerId -> metadata. Ham anahtar burada hiçbir zaman yer almaz.
  const owners = new Map<string, Map<ProviderId, ApiKeyMetadata>>();

  function ownerMap(ownerId: string): Map<ProviderId, ApiKeyMetadata> {
    let map = owners.get(ownerId);
    if (!map) {
      map = new Map();
      owners.set(ownerId, map);
    }
    return map;
  }

  function read(ownerId: string, providerId: ProviderId): ApiKeyMetadata {
    const entry = owners.get(ownerId)?.get(providerId);
    return entry ? { ...entry } : emptyMetadata(providerId);
  }

  return {
    forOwner(ownerId) {
      return {
        async listKeys() {
          await wait(delayMs);
          return DEMO_PROVIDERS.map((provider) => read(ownerId, provider.id));
        },

        async saveKey(providerId, rawKey) {
          await wait(delayMs);
          if (validateApiKeyInput(rawKey)) return { ok: false, error: "invalid_input" };
          if (getScenarios(providerId).save === "unexpected_error") {
            return { ok: false, error: "unexpected_error" };
          }
          const value = rawKey.trim();
          const metadata: ApiKeyMetadata = {
            providerId,
            status: "saved_unverified",
            last4: value.length >= LAST4_MIN_LENGTH ? value.slice(-4) : null,
            updatedAt: new Date(),
            simulated: true,
          };
          ownerMap(ownerId).set(providerId, metadata);
          return { ok: true, key: { ...metadata } };
        },

        async checkKey(providerId) {
          await wait(delayMs);
          const current = owners.get(ownerId)?.get(providerId);
          if (!current) return { ok: false, error: "not_configured" };
          const metadata: ApiKeyMetadata = {
            ...current,
            status: SCENARIO_STATUS[getScenarios(providerId).verify],
            simulated: true,
          };
          ownerMap(ownerId).set(providerId, metadata);
          return { ok: true, key: { ...metadata } };
        },

        async deleteKey(providerId) {
          await wait(delayMs);
          owners.get(ownerId)?.delete(providerId);
          return { ok: true, key: emptyMetadata(providerId) };
        },
      };
    },

    clearOwner(ownerId) {
      owners.delete(ownerId);
    },
  };
}
