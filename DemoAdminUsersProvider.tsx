/**
 * Demo yönetici kullanıcı store'unu sağlar. Servis yalnızca demo `admin`
 * oturumuna verilir; `analyst` oturumunda `service` null'dır. Bu bir arayüz
 * sınırıdır, gerçek güvenlik kontrolü değildir.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { DEFAULT_ADMIN_USER_SCENARIOS, createMockAdminUserStore } from "./demoAdminService";
import type { AdminUserScenarios, DemoAdminUserStore } from "./demoAdminService";
import { DemoAdminUsersContext } from "./useDemoAdminUsers";
import type { DemoAdminUsersContextValue } from "./useDemoAdminUsers";
import { useDemoSession } from "./useDemoSession";

export function DemoAdminUsersProvider({ children }: { children: ReactNode }) {
  const { session } = useDemoSession();
  const [scenarios, setScenarios] = useState<AdminUserScenarios>(DEFAULT_ADMIN_USER_SCENARIOS);
  const scenariosRef = useRef(scenarios);
  useEffect(() => {
    scenariosRef.current = scenarios;
  }, [scenarios]);

  const [store] = useState<DemoAdminUserStore>(() =>
    createMockAdminUserStore({ getScenarios: () => scenariosRef.current }),
  );

  const actor = session?.account ?? null;
  const service = useMemo(
    () => (actor && actor.role === "admin" ? store.forActor(actor) : null),
    [actor, store],
  );

  const setScenario = useCallback<DemoAdminUsersContextValue["setScenario"]>(
    (key, value) => setScenarios((prev) => ({ ...prev, [key]: value })),
    [],
  );

  const value = useMemo<DemoAdminUsersContextValue>(
    () => ({ service, scenarios, setScenario }),
    [service, scenarios, setScenario],
  );

  return <DemoAdminUsersContext.Provider value={value}>{children}</DemoAdminUsersContext.Provider>;
}
