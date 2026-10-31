/**
 * Demo API anahtarı store'unu ve geliştirici paneli senaryolarını sağlar.
 *
 * Ekranlara yalnızca o anki demo oturumuna (`sessionId`) bağlı servis verilir.
 * Demo oturumu kapandığında veya değiştiğinde önceki oturumun metadata'sı
 * silinir; böylece oturumlar arasında anahtar bilgisi paylaşılmaz.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { DEFAULT_API_KEY_SCENARIOS, createMockApiKeyStore } from "./demoApiKeyService";
import type { ApiKeyScenarios, DemoApiKeyStore } from "./demoApiKeyService";
import type { ProviderId } from "./demoProviders";
import { DemoApiKeysContext } from "./useDemoApiKeys";
import type { DemoApiKeysContextValue } from "./useDemoApiKeys";
import { useDemoSession } from "./useDemoSession";

type ScenarioMap = Partial<Record<ProviderId, ApiKeyScenarios>>;

export function DemoApiKeysProvider({ children }: { children: ReactNode }) {
  const { session } = useDemoSession();
  const ownerId = session?.sessionId ?? null;

  const [scenarios, setScenarios] = useState<ScenarioMap>({});
  const scenariosRef = useRef(scenarios);
  useEffect(() => {
    scenariosRef.current = scenarios;
  }, [scenarios]);

  const getScenarios = useCallback(
    (providerId: ProviderId) => scenarios[providerId] ?? DEFAULT_API_KEY_SCENARIOS,
    [scenarios],
  );

  const [store] = useState<DemoApiKeyStore>(() =>
    createMockApiKeyStore({
      getScenarios: (providerId) =>
        scenariosRef.current[providerId] ?? DEFAULT_API_KEY_SCENARIOS,
    }),
  );

  // Oturum kapanınca/değişince önceki sahibin metadata'sını sil.
  useEffect(() => {
    if (!ownerId) return;
    return () => store.clearOwner(ownerId);
  }, [ownerId, store]);

  const setScenario = useCallback<DemoApiKeysContextValue["setScenario"]>(
    (providerId, key, value) =>
      setScenarios((prev) => ({
        ...prev,
        [providerId]: { ...(prev[providerId] ?? DEFAULT_API_KEY_SCENARIOS), [key]: value },
      })),
    [],
  );

  const service = useMemo(() => (ownerId ? store.forOwner(ownerId) : null), [ownerId, store]);

  const value = useMemo<DemoApiKeysContextValue>(
    () => ({ service, ownerId, getScenarios, setScenario }),
    [service, ownerId, getScenarios, setScenario],
  );

  return <DemoApiKeysContext.Provider value={value}>{children}</DemoApiKeysContext.Provider>;
}
