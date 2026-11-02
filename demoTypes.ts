/**
 * Demo prototipi tipleri.
 *
 * SINIR: Bu modül ve `src/demo/` altındaki her şey gerçek auth katmanından
 * (`src/auth/`) bağımsızdır. Yalnızca rol adları tek kaynaktan gelsin diye
 * `UserRole` tipi (type-only) paylaşılır; gerçek AuthProvider, token store veya
 * API istemcisi buradan hiçbir zaman import edilmez.
 */

import type { UserRole } from "@/auth/authTypes";

/** Demo rolü — mevcut backend rolleriyle aynı değerler: "admin" | "analyst". */
export type DemoRole = UserRole;

/** Sahte demo hesabı. Gerçek bir kullanıcıya veya e-postaya karşılık gelmez. */
export interface DemoAccount {
  id: string;
  displayName: string;
  role: DemoRole;
}

/**
 * Bellekteki demo oturumu.
 *
 * SECURITY: token, parola, API anahtarı veya doğrulama kodu İÇERMEZ ve
 * localStorage/sessionStorage içine yazılmaz.
 */
export interface DemoSession {
  /**
   * Her demo girişinde yeni üretilen kimlik. Demo verilerinin (ör. API anahtarı
   * metadata'sı) sahiplik sınırıdır; aynı rolle yeniden giriş yeni bir oturumdur.
   * Gerçek bir backend kullanıcı kimliği DEĞİLDİR.
   */
  sessionId: string;
  account: DemoAccount;
  startedAt: Date;
}

export interface DemoSessionContextValue {
  session: DemoSession | null;
  accounts: readonly DemoAccount[];
  startSession: (accountId: string) => Promise<void>;
  endSession: () => Promise<void>;
}

/** Arayüzde gösterilen rol etiketleri; değerler yeniden adlandırılmaz. */
export const DEMO_ROLE_LABELS: Record<DemoRole, string> = {
  admin: "Yönetici",
  analyst: "Kullanıcı",
};
