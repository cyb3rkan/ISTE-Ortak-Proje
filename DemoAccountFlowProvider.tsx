/**
 * Demo hesap akışlarının bellek içi durumu: mock servis, geliştirici paneli
 * senaryoları ve doğrulama bekleyen e-posta. Gerçek auth katmanından bağımsızdır.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import {
  DEFAULT_DEMO_SCENARIOS,
  createMockDemoAccountService,
} from "./demoAccountService";
import type { DemoAccountScenarios, DemoAccountService } from "./demoAccountService";
import { DemoAccountFlowContext } from "./useDemoAccountFlow";
import type { DemoAccountFlowContextValue } from "./useDemoAccountFlow";

interface DemoAccountFlowProviderProps {
  children: ReactNode;
  /** İleride gerçek adaptörle değiştirilebilir. */
  service?: DemoAccountService;
}

export function DemoAccountFlowProvider({ children, service }: DemoAccountFlowProviderProps) {
  const [scenarios, setScenarios] = useState<DemoAccountScenarios>(DEFAULT_DEMO_SCENARIOS);
  const [pendingEmail, setPendingEmail] = useState<string | null>(null);

  // Mock servis her çağrıda güncel senaryoyu okusun diye ref kullanılır.
  const scenariosRef = useRef(scenarios);
  useEffect(() => {
    scenariosRef.current = scenarios;
  }, [scenarios]);

  const activeService = useMemo(
    () =>
      service ??
      createMockDemoAccountService({ getScenarios: () => scenariosRef.current }),
    [service],
  );

  const setScenario = useCallback<DemoAccountFlowContextValue["setScenario"]>(
    (key, value) => setScenarios((prev) => ({ ...prev, [key]: value })),
    [],
  );

  const value = useMemo<DemoAccountFlowContextValue>(
    () => ({
      service: activeService,
      pendingEmail,
      setPendingEmail,
      scenarios,
      setScenario,
    }),
    [activeService, pendingEmail, scenarios, setScenario],
  );

  return (
    <DemoAccountFlowContext.Provider value={value}>{children}</DemoAccountFlowContext.Provider>
  );
}
