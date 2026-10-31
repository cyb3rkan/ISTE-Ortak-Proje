/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  /** UI auth mode: "disabled" (local demo) | "jwt" (login required). */
  readonly VITE_AUTH_MODE?: string;
  /** Enables the mock multi-user UI prototype under /demo: "true" | "1". */
  readonly VITE_PROTOTYPE_MODE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
