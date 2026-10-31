import { createContext, useContext } from "react";

import type { AdminUserScenarios, DemoAdminUserService } from "./demoAdminService";

export interface DemoAdminUsersContextValue {
  /** Yalnızca demo `admin` oturumunda verilir; aksi halde null. */
  service: DemoAdminUserService | null;
  scenarios: AdminUserScenarios;
  setScenario: <K extends keyof AdminUserScenarios>(
    key: K,
    value: AdminUserScenarios[K],
  ) => void;
}

export const DemoAdminUsersContext = createContext<DemoAdminUsersContextValue | null>(null);

export function useDemoAdminUsers(): DemoAdminUsersContextValue {
  const ctx = useContext(DemoAdminUsersContext);
  if (ctx === null) {
    throw new Error("useDemoAdminUsers must be used within a <DemoAdminUsersProvider>");
  }
  return ctx;
}
