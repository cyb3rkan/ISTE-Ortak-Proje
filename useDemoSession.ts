import { createContext, useContext } from "react";

import type { DemoSessionContextValue } from "./demoTypes";

/** Gerçek `AuthContext`'ten ayrı, yalnızca demo alanına ait context. */
export const DemoSessionContext = createContext<DemoSessionContextValue | null>(
  null,
);

export function useDemoSession(): DemoSessionContextValue {
  const ctx = useContext(DemoSessionContext);
  if (ctx === null) {
    throw new Error("useDemoSession must be used within a <DemoSessionProvider>");
  }
  return ctx;
}
