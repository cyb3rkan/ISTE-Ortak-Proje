/**
 * Yönetici kullanıcı yönetimi — demo servis sınırı.
 *
 * VERİ MİNİMİZASYONU: `DemoManagedUser` yalnızca hesap yönetimi için gereken
 * alanları içerir (kimlik, görünen ad, demo e-posta, rol, hesap ve e-posta
 * doğrulama durumu). API anahtarı, sağlayıcı yapılandırması, IOC analizi,
 * rapor, parola, kod veya token alanı YOKTUR ve bu servis bunları istemez.
 *
 * YETKİ: Servis, onu kullanan aktöre bağlanır (`forActor`). Mock da backend
 * gibi davranır: admin olmayan aktörü reddeder, aktörün kendi hesabını ve
 * yönetici hesaplarını değiştirmeyi reddeder. Bu yalnızca prototip
 * davranışıdır; gerçek yetkilendirme backend'de uygulanmalıdır.
 *
 * Değişiklikler yalnızca bellekte tutulur; web storage veya ağ kullanılmaz.
 * Rol değiştirme, yönetici atama, hesap silme ve parola sıfırlama işlemi yoktur.
 */

import type { DemoAccount, DemoRole } from "./demoTypes";

export type DemoAccountStatus = "active" | "disabled";
export type DemoEmailVerification = "verified" | "pending";

export interface DemoManagedUser {
  id: string;
  displayName: string;
  /** Açıkça sahte, `.invalid` alan adlı demo adresi. */
  demoEmail: string;
  role: DemoRole;
  accountStatus: DemoAccountStatus;
  emailVerification: DemoEmailVerification;
  /** Kayıt, servisi kullanan aktörün kendi hesabı mı. */
  isSelf: boolean;
}

export type ListUsersResult =
  | { ok: true; users: DemoManagedUser[] }
  | { ok: false; error: "forbidden" | "unexpected_error" };

export type SetAccountStatusResult =
  | { ok: true; user: DemoManagedUser }
  | {
      ok: false;
      error:
        | "forbidden"
        | "self_action_forbidden"
        | "admin_protected"
        | "not_found"
        | "unexpected_error";
    };

export interface DemoAdminUserService {
  listUsers(): Promise<ListUsersResult>;
  setAccountStatus(userId: string, status: DemoAccountStatus): Promise<SetAccountStatusResult>;
}

export interface DemoAdminUserStore {
  forActor(actor: DemoAccount): DemoAdminUserService;
}

export interface AdminUserScenarios {
  list: "success" | "empty" | "error";
  update: "success" | "error";
}

export const DEFAULT_ADMIN_USER_SCENARIOS: AdminUserScenarios = {
  list: "success",
  update: "success",
};

type StoredUser = Omit<DemoManagedUser, "isSelf">;

/**
 * Açıkça sahte demo fixture'ları. Tek yönetici varsayımı korunur: yalnızca
 * demo giriş ekranındaki "Demo Yönetici" hesabı admin rolündedir.
 */
const DEMO_USER_FIXTURES: readonly StoredUser[] = [
  {
    id: "demo-admin",
    displayName: "Demo Yönetici",
    demoEmail: "yonetici@demo.invalid",
    role: "admin",
    accountStatus: "active",
    emailVerification: "verified",
  },
  {
    id: "demo-user-1",
    displayName: "Örnek Kullanıcı 1",
    demoEmail: "kullanici-1@demo.invalid",
    role: "analyst",
    accountStatus: "active",
    emailVerification: "verified",
  },
  {
    id: "demo-user-2",
    displayName: "Örnek Kullanıcı 2",
    demoEmail: "kullanici-2@demo.invalid",
    role: "analyst",
    accountStatus: "active",
    emailVerification: "pending",
  },
  {
    id: "demo-user-3",
    displayName: "Örnek Kullanıcı 3",
    demoEmail: "kullanici-3@demo.invalid",
    role: "analyst",
    accountStatus: "disabled",
    emailVerification: "verified",
  },
  {
    id: "demo-user-4",
    displayName: "Örnek Kullanıcı 4",
    demoEmail: "kullanici-4@demo.invalid",
    role: "analyst",
    accountStatus: "active",
    emailVerification: "verified",
  },
];

interface MockOptions {
  getScenarios: () => AdminUserScenarios;
  delayMs?: number;
}

function wait(ms: number): Promise<void> {
  return ms > 0 ? new Promise((resolve) => setTimeout(resolve, ms)) : Promise.resolve();
}

export function createMockAdminUserStore({
  getScenarios,
  delayMs = 300,
}: MockOptions): DemoAdminUserStore {
  // Yalnızca bellekte; fixture dizisi kopyalanır, böylece kaynak değişmez.
  const users = new Map<string, StoredUser>(
    DEMO_USER_FIXTURES.map((user) => [user.id, { ...user }]),
  );

  function view(user: StoredUser, actor: DemoAccount): DemoManagedUser {
    return { ...user, isSelf: user.id === actor.id };
  }

  return {
    forActor(actor) {
      const isAdmin = actor.role === "admin";
      return {
        async listUsers() {
          await wait(delayMs);
          if (!isAdmin) return { ok: false, error: "forbidden" };
          const scenario = getScenarios().list;
          if (scenario === "error") return { ok: false, error: "unexpected_error" };
          if (scenario === "empty") return { ok: true, users: [] };
          return { ok: true, users: [...users.values()].map((u) => view(u, actor)) };
        },

        async setAccountStatus(userId, status) {
          await wait(delayMs);
          if (!isAdmin) return { ok: false, error: "forbidden" };
          if (userId === actor.id) return { ok: false, error: "self_action_forbidden" };
          const current = users.get(userId);
          if (!current) return { ok: false, error: "not_found" };
          if (current.role === "admin") return { ok: false, error: "admin_protected" };
          if (getScenarios().update === "error") return { ok: false, error: "unexpected_error" };
          const updated: StoredUser = { ...current, accountStatus: status };
          users.set(userId, updated);
          return { ok: true, user: view(updated, actor) };
        },
      };
    },
  };
}
