import { AppRoutes } from "@/routes";

/**
 * Providers are mounted per route area in `routes.tsx`: the real app layout
 * route owns `AuthProvider` + `AppShell`, while the optional `/demo`
 * prototype mounts only its own demo providers (no real auth, no backend calls).
 */
export function App() {
  return <AppRoutes />;
}
