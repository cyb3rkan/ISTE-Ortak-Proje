/**
 * Demo servis/adaptör sınırı.
 *
 * Ekran bileşenleri mock verilere doğrudan değil, bu arayüzler üzerinden
 * erişir; backend entegrasyonunda mock uygulama gerçek bir adaptörle
 * değiştirilebilir. Endpoint sözleşmesi henüz yoktur ve burada uydurulmaz.
 *
 * Sonraki aşamalarda bu modülün yanına ayrı arayüzler eklenecek:
 *  - e-posta doğrulama ve parola sıfırlama,
 *  - kullanıcının kendi sağlayıcı API anahtarları (bkz. demoApiKeyService.ts),
 *  - yönetici kullanıcı yönetimi (anahtar değeri ve analiz içermeden).
 */

import type { DemoAccount, DemoSession } from "./demoTypes";

export interface DemoSessionService {
  listAccounts(): readonly DemoAccount[];
  startSession(accountId: string): Promise<DemoSession>;
  endSession(): Promise<void>;
}

/** Açıkça sahte demo hesapları — gerçek kişi veya e-posta içermez. */
const DEMO_ACCOUNTS: readonly DemoAccount[] = Object.freeze([
  Object.freeze({ id: "demo-analyst", displayName: "Demo Kullanıcı", role: "analyst" }),
  Object.freeze({ id: "demo-admin", displayName: "Demo Yönetici", role: "admin" }),
]);

export class UnknownDemoAccountError extends Error {
  constructor() {
    super("Seçilen demo hesabı bulunamadı.");
    this.name = "UnknownDemoAccountError";
  }
}

let sessionCounter = 0;

/** Mock uygulama: ağ isteği yapmaz, hiçbir şeyi kalıcı olarak saklamaz. */
export const mockDemoSessionService: DemoSessionService = {
  listAccounts() {
    return DEMO_ACCOUNTS;
  },

  async startSession(accountId) {
    const account = DEMO_ACCOUNTS.find((item) => item.id === accountId);
    if (!account) {
      throw new UnknownDemoAccountError();
    }
    sessionCounter += 1;
    return {
      sessionId: `demo-session-${sessionCounter}-${Date.now()}`,
      account,
      startedAt: new Date(),
    };
  },

  async endSession() {
    // Mock oturum yalnızca bellekte yaşar; sunucu tarafında kapatılacak bir şey yoktur.
  },
};
