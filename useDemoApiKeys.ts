import { createContext, useContext } from "react";

import type { ApiKeyScenarios, DemoApiKeyService } from "./demoApiKeyService";
import type { ProviderId } from "./demoProviders";

export interface DemoApiKeysContextValue {
  /** Yalnızca o anki demo oturumuna bağlı servis; oturum yoksa null. */
  service: DemoApiKeyService | null;
  /** Servisin bağlı olduğu demo oturumu (sahiplik sınırı). */
  ownerId: string | null;
  getScenarios: (providerId: ProviderId) => ApiKeyScenarios;
  setScenario: <K extends keyof ApiKeyScenarios>(
    providerId: ProviderId,
    key: K,
    value: ApiKeyScenarios[K],
  ) => void;
}

export const DemoApiKeysContext = createContext<DemoApiKeysContextValue | null>(null);

export function useDemoApiKeys(): DemoApiKeysContextValue {
  const ctx = useContext(DemoApiKeysContext);
  if (ctx === null) {
    throw new Error("useDemoApiKeys must be used within a <DemoApiKeysProvider>");
  }
  return ctx;
}
