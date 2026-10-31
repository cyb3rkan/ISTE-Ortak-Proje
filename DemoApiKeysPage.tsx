/**
 * "API Anahtarlarım" — kullanıcıya ait sağlayıcı anahtarları (demo).
 *
 * Gerçek uygulamadaki "Provider'lar" sayfasından ayrıdır: o sayfa sunucu
 * genelindeki yapılandırmayı gösterir, bu sayfa yalnızca o anki demo
 * oturumunun kendi anahtar metadata'sını gösterir. Backend'e istek atmaz.
 */

import { useCallback, useEffect, useState } from "react";
import { useLocation } from "react-router";

import { LoadingState } from "@/components/common/LoadingState";
import { ApiKeyCard } from "../components/ApiKeyCard";
import { ApiKeyDevPanel } from "../components/ApiKeyDevPanel";
import { DEMO_ALERT } from "../components/DemoAuthCard";
import { API_KEY_ERROR_STATUSES } from "../demoApiKeyService";
import type { ApiKeyMetadata } from "../demoApiKeyService";
import { DEMO_PROVIDERS } from "../demoProviders";
import { useDemoApiKeys } from "../useDemoApiKeys";
import { useDemoSession } from "../useDemoSession";

function readFocusProvider(state: unknown): string | null {
  if (typeof state !== "object" || state === null || !("focusProvider" in state)) return null;
  const value = (state as { focusProvider: unknown }).focusProvider;
  return typeof value === "string" ? value : null;
}

export function DemoApiKeysPage() {
  const { session } = useDemoSession();
  const { service } = useDemoApiKeys();
  const focusProvider = readFocusProvider(useLocation().state);

  const [keys, setKeys] = useState<ApiKeyMetadata[] | null>(null);
  const [loadError, setLoadError] = useState(false);

  const load = useCallback(async () => {
    if (!service) return;
    setLoadError(false);
    try {
      setKeys(await service.listKeys());
    } catch {
      setLoadError(true);
    }
  }, [service]);

  useEffect(() => {
    setKeys(null);
    void load();
  }, [load]);

  const handleChange = useCallback((updated: ApiKeyMetadata) => {
    setKeys((prev) =>
      prev ? prev.map((k) => (k.providerId === updated.providerId ? updated : k)) : prev,
    );
  }, []);

  if (!session || !service) return null;

  const problemCount = keys?.filter((k) => API_KEY_ERROR_STATUSES.includes(k.status)).length ?? 0;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold text-slate-100">API Anahtarlarım</h1>
        <p className="mt-1 text-sm text-slate-400">
          Bu sayfa yalnızca bu demo oturumuna ait sağlayıcı anahtarlarını gösterir. Anahtarlar
          sağlayıcılara gönderilmez; demo kayıtları yalnızca bellekte tutulur ve sayfa
          yenilendiğinde veya demo oturumu kapandığında silinir.
        </p>
      </div>

      <div className="rounded-lg border border-surface-border bg-surface-raised px-4 py-3 text-xs text-slate-300">
        <p>
          Gerçek uygulamadaki “Provider'lar” sayfası, sunucu genelindeki sağlayıcı
          yapılandırmasını ve çalışma durumunu gösterir. Buradaki kişisel demo anahtarları o
          sayfayı veya gerçek analizleri etkilemez.
        </p>
        {session.account.role === "admin" ? (
          <p className="mt-2 text-slate-400">
            Yönetici rolü, başka kullanıcıların anahtarlarını görme yetkisi vermez; burada
            yalnızca kendi demo anahtarlarınız görünür.
          </p>
        ) : null}
      </div>

      {problemCount > 0 ? (
        <p className="rounded-md border border-risk-medium/40 bg-risk-medium/10 px-3 py-2 text-xs text-slate-200">
          {problemCount} sağlayıcıda sorun var. Her sorun yalnızca ilgili sağlayıcıyı etkiler;
          diğer sağlayıcıların sonuçları kullanılabilir kalır.
        </p>
      ) : null}

      {loadError ? (
        <div role="alert" className={DEMO_ALERT}>
          Anahtar durumları yüklenemedi.{" "}
          <button type="button" onClick={() => void load()} className="underline">
            Tekrar dene
          </button>
        </div>
      ) : null}

      {!keys && !loadError ? <LoadingState label="Anahtar durumları yükleniyor…" /> : null}

      {keys ? (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {DEMO_PROVIDERS.map((provider) => {
            const metadata = keys.find((k) => k.providerId === provider.id);
            if (!metadata) return null;
            return (
              <ApiKeyCard
                key={`${session.sessionId}-${provider.id}`}
                provider={provider}
                metadata={metadata}
                service={service}
                onChange={handleChange}
                focusInputOnMount={focusProvider === provider.id}
              />
            );
          })}
        </div>
      ) : null}

      <ApiKeyDevPanel />
    </div>
  );
}
