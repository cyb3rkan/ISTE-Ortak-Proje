/**
 * Demo oturum sağlayıcısı.
 *
 * Gerçek `AuthProvider`'dan bağımsızdır: tokenStore'a, refresh akışına veya
 * backend'e dokunmaz. Oturum yalnızca React state içinde tutulur; sayfa
 * yenilendiğinde veya demo alanından çıkıldığında silinir.
 */

import { useCallback, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { mockDemoSessionService } from "./demoSessionService";
import type { DemoSessionService } from "./demoSessionService";
import type { DemoSession, DemoSessionContextValue } from "./demoTypes";
import { DemoSessionContext } from "./useDemoSession";

interface DemoSessionProviderProps {
  children: ReactNode;
  /** Testlerde veya ileride gerçek adaptörle değiştirilebilir. */
  service?: DemoSessionService;
}

export function DemoSessionProvider({
  children,
  service = mockDemoSessionService,
}: DemoSessionProviderProps) {
  const [session, setSession] = useState<DemoSession | null>(null);

  const startSession = useCallback(
    async (accountId: string) => {
      setSession(await service.startSession(accountId));
    },
    [service],
  );

  const endSession = useCallback(async () => {
    try {
      await service.endSession();
    } finally {
      setSession(null);
    }
  }, [service]);

  const value = useMemo<DemoSessionContextValue>(
    () => ({
      session,
      accounts: service.listAccounts(),
      startSession,
      endSession,
    }),
    [session, service, startSession, endSession],
  );

  return (
    <DemoSessionContext.Provider value={value}>
      {children}
    </DemoSessionContext.Provider>
  );
}
