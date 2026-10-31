/**
 * Geliştirici demo paneli — API anahtarı durum senaryoları.
 *
 * Yalnızca demo arayüz durumunu değiştirir: seçim, ilgili sağlayıcı kartındaki
 * bir sonraki "Kaydet" veya "Bağlantıyı dene (demo)" işleminde uygulanır.
 * Ağ isteği veya kalıcı kayıt yapmaz.
 */

import { useState } from "react";

import type { ApiKeyScenarios, VerificationScenario } from "../demoApiKeyService";
import { DEMO_PROVIDERS } from "../demoProviders";
import type { ProviderId } from "../demoProviders";
import { useDemoApiKeys } from "../useDemoApiKeys";

const VERIFY_OPTIONS: { value: VerificationScenario; label: string }[] = [
  { value: "not_verified", label: "Demo: bağlanılmadı (varsayılan)" },
  { value: "invalid", label: "Anahtar geçersiz" },
  { value: "permission_denied", label: "Erişim/izin yok" },
  { value: "rate_limited", label: "Kota veya hız sınırı" },
  { value: "provider_unreachable", label: "Sağlayıcıya ulaşılamıyor" },
  { value: "unexpected_error", label: "Beklenmeyen hata" },
];

const SAVE_OPTIONS: { value: ApiKeyScenarios["save"]; label: string }[] = [
  { value: "saved", label: "Demo kayıt" },
  { value: "unexpected_error", label: "Beklenmeyen hata" },
];

const SELECT =
  "mt-1 w-full rounded-md border border-surface-border bg-surface px-3 py-2 text-sm text-slate-100 focus:border-accent focus:outline-hidden focus-visible:outline-2 focus-visible:outline-accent";

export function ApiKeyDevPanel() {
  const { getScenarios, setScenario } = useDemoApiKeys();
  const [providerId, setProviderId] = useState<ProviderId>("shodan");
  const scenarios = getScenarios(providerId);

  return (
    <fieldset className="rounded-lg border border-dashed border-slate-600 px-4 pb-4 pt-2">
      <legend className="px-1 font-mono text-[11px] font-semibold uppercase tracking-wide text-slate-400">
        Geliştirici demo paneli
      </legend>
      <p className="text-xs text-slate-400">
        Yalnızca prototipteki durumları denemek içindir; gerçek uygulamada bulunmaz. Seçim,
        ilgili kartta bir sonraki “Kaydet” veya “Bağlantıyı dene (demo)” işleminde uygulanır.
        Sağlayıcıya bağlanmaz, ağ isteği veya kalıcı kayıt yapmaz.
      </p>
      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <div>
          <label htmlFor="api-key-scenario-provider" className="text-xs font-medium text-slate-400">
            Sağlayıcı
          </label>
          <select
            id="api-key-scenario-provider"
            value={providerId}
            onChange={(e) => setProviderId(e.target.value as ProviderId)}
            className={SELECT}
          >
            {DEMO_PROVIDERS.map((provider) => (
              <option key={provider.id} value={provider.id}>
                {provider.name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="api-key-scenario-verify" className="text-xs font-medium text-slate-400">
            Bağlantı denemesi sonucu
          </label>
          <select
            id="api-key-scenario-verify"
            value={scenarios.verify}
            onChange={(e) =>
              setScenario(providerId, "verify", e.target.value as VerificationScenario)
            }
            className={SELECT}
          >
            {VERIFY_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="api-key-scenario-save" className="text-xs font-medium text-slate-400">
            Kaydetme sonucu
          </label>
          <select
            id="api-key-scenario-save"
            value={scenarios.save}
            onChange={(e) =>
              setScenario(providerId, "save", e.target.value as ApiKeyScenarios["save"])
            }
            className={SELECT}
          >
            {SAVE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      </div>
    </fieldset>
  );
}
