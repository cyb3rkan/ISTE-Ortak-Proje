import { createContext, useContext } from "react";

import type { DemoAccountScenarios, DemoAccountService } from "./demoAccountService";

export interface DemoAccountFlowContextValue {
  service: DemoAccountService;
  /**
   * Doğrulama bekleyen demo kaydının e-postası (yalnızca bellekte).
   * Parola veya kod hiçbir zaman burada tutulmaz.
   */
  pendingEmail: string | null;
  setPendingEmail: (email: string | null) => void;
  scenarios: DemoAccountScenarios;
  setScenario: <K extends keyof DemoAccountScenarios>(
    key: K,
    value: DemoAccountScenarios[K],
  ) => void;
}

export const DemoAccountFlowContext = createContext<DemoAccountFlowContextValue | null>(
  null,
);

export function useDemoAccountFlow(): DemoAccountFlowContextValue {
  const ctx = useContext(DemoAccountFlowContext);
  if (ctx === null) {
    throw new Error("useDemoAccountFlow must be used within a <DemoAccountFlowProvider>");
  }
  return ctx;
}
