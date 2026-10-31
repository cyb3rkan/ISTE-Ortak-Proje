/**
 * Demo prototipi (Aşama 4) — yönetici kullanıcı ekranı.
 *
 *  - Rota yalnızca `VITE_PROTOTYPE_MODE` açıkken ve demo `admin` oturumunda erişilir.
 *  - `analyst` oturumu listeyi/eylemleri göremez; mock servis de reddeder.
 *  - Etkin/pasif değişikliği onay ister; admin kendi hesabını değiştiremez.
 *  - Yönetici arayüzünde API anahtarı veya analiz/rapor verisi yoktur.
 *  - Değişiklikler web storage'a yazılmaz; ağ isteği yapılmaz.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RouterProvider, createMemoryRouter } from "react-router";

const flags = vi.hoisted(() => ({ prototypeMode: false }));

vi.mock("@/lib/config", async () => {
  const actual =
    await vi.importActual<typeof import("@/lib/config")>("@/lib/config");
  return {
    ...actual,
    config: {
      ...actual.config,
      // Yerel .env(.local) dosyalarından bağımsız, deterministik auth modu.
      authMode: "disabled",
      get prototypeMode() {
        return flags.prototypeMode;
      },
    },
  };
});

import { App } from "@/App";
import { createMockAdminUserStore } from "@/demo/demoAdminService";
import type { DemoAccount } from "@/demo/demoTypes";

const FAKE_KEY = "demo-sahte-anahtar-0000abcd";
type User = ReturnType<typeof userEvent.setup>;

function renderApp(path: string) {
  const router = createMemoryRouter([{ path: "*", element: <App /> }], {
    initialEntries: [path],
  });
  render(<RouterProvider router={router} />);
  return router;
}

async function loginAs(user: User, role: "Kullanıcı" | "Yönetici") {
  await user.click(screen.getByRole("radio", { name: new RegExp(`^${role}`, "i") }));
  await user.click(screen.getByRole("button", { name: /demo alanına gir/i }));
  await screen.findByRole("heading", { name: /demo kontrol paneli/i });
}

async function openUserAdmin(user: User) {
  await user.click(screen.getByRole("link", { name: "Kullanıcı yönetimi" }));
  await screen.findByRole("heading", { name: "Kullanıcı yönetimi", level: 1 });
  return screen.findByRole("list", { name: "Demo kullanıcıları" });
}

function userItem(name: string) {
  const list = screen.getByRole("list", { name: "Demo kullanıcıları" });
  const item = within(list)
    .getAllByRole("listitem")
    .find((li) => within(li).queryByRole("heading", { name: new RegExp(name) }));
  if (!item) throw new Error(`Kullanıcı bulunamadı: ${name}`);
  return item;
}

describe("demo yönetici kullanıcı ekranı", () => {
  const fetchMock = vi.fn();
  let setItemSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockRejectedValue(new Error("network disabled in tests"));
    vi.stubGlobal("fetch", fetchMock);
    setItemSpy = vi.spyOn(Storage.prototype, "setItem");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    flags.prototypeMode = false;
  });

  it("bayrak kapalıyken yönetici rotası mevcut 404 sayfasına düşer", () => {
    renderApp("/demo/admin/users");
    expect(screen.getByText("404")).toBeInTheDocument();
    expect(screen.queryByText(/kullanıcı yönetimi/i)).not.toBeInTheDocument();
  });

  describe("VITE_PROTOTYPE_MODE açıkken", () => {
    beforeEach(() => {
      flags.prototypeMode = true;
    });

    it("demo oturumu yokken demo girişine yönlendirir", () => {
      renderApp("/demo/admin/users");
      expect(screen.getByRole("heading", { name: /demo girişi/i })).toBeInTheDocument();
    });

    it("analyst bağlantıyı görmez; rotaya girerse liste yerine erişim reddi görür", async () => {
      const user = userEvent.setup();
      const router = renderApp("/demo/login");
      await loginAs(user, "Kullanıcı");

      expect(screen.queryByRole("link", { name: "Kullanıcı yönetimi" })).not.toBeInTheDocument();

      await act(() => router.navigate("/demo/admin/users"));
      expect(
        await screen.findByRole("heading", { name: /erişim reddedildi/i }),
      ).toBeInTheDocument();
      expect(screen.queryByRole("list", { name: "Demo kullanıcıları" })).not.toBeInTheDocument();
      expect(screen.queryByText(/örnek kullanıcı/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/demo\.invalid/i)).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /devre dışı bırak|etkinleştir/i })).toBeNull();
      expect(screen.getByRole("link", { name: /kontrol paneline dön/i })).toBeInTheDocument();
    });

    it("admin sahte listeyi, hesap ve e-posta durumlarını görür", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Yönetici");
      const list = await openUserAdmin(user);

      expect(within(list).getAllByRole("listitem")).toHaveLength(5);
      expect(screen.getAllByText(/demo prototipi/i).length).toBeGreaterThan(0);
      expect(screen.getByText(/gerçek hesapları yönetmez/i)).toBeInTheDocument();
      expect(screen.getByText(/backend tarafından uygulanmalıdır/i)).toBeInTheDocument();

      const passive = userItem("Örnek Kullanıcı 3");
      expect(within(passive).getByText("Pasif")).toBeInTheDocument();
      const pending = userItem("Örnek Kullanıcı 2");
      expect(within(pending).getByText("Doğrulama bekliyor")).toBeInTheDocument();
      expect(within(pending).getByText("kullanici-2@demo.invalid")).toBeInTheDocument();

      // Tek yönetici: yalnızca oturumdaki admin.
      expect(within(list).getAllByText("Yönetici")).toHaveLength(1);
    });

    it("durum değişikliği onay ister; Escape iptal eder, onay sonrası durum değişir", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Yönetici");
      await openUserAdmin(user);

      const target = userItem("Örnek Kullanıcı 1");
      const action = within(target).getByRole("button", {
        name: "Örnek Kullanıcı 1 hesabını devre dışı bırak",
      });
      await user.click(action);
      const dialog = screen.getByRole("dialog", { name: /örnek kullanıcı 1 hesabı devre dışı bırakılsın mı/i });
      expect(within(dialog).getByRole("button", { name: "Vazgeç" })).toHaveFocus();
      expect(dialog).toHaveTextContent(/yalnızca demo belleğindeki/i);

      await user.keyboard("{Escape}");
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(action).toHaveFocus();
      expect(within(userItem("Örnek Kullanıcı 1")).getByText("Etkin")).toBeInTheDocument();

      await user.click(action);
      await user.click(
        within(screen.getByRole("dialog")).getByRole("button", { name: "Devre dışı bırak" }),
      );
      expect(await within(userItem("Örnek Kullanıcı 1")).findByText("Pasif")).toBeInTheDocument();
      expect(screen.getByRole("status", { name: "İşlem sonucu" })).toHaveTextContent(
        /örnek kullanıcı 1 hesabı devre dışı bırakıldı/i,
      );

      // Pasif hesap yeniden etkinleştirilebilir (yine onayla).
      await user.click(
        within(userItem("Örnek Kullanıcı 1")).getByRole("button", {
          name: "Örnek Kullanıcı 1 hesabını etkinleştir",
        }),
      );
      await user.click(
        within(screen.getByRole("dialog")).getByRole("button", { name: "Etkinleştir" }),
      );
      expect(await within(userItem("Örnek Kullanıcı 1")).findByText("Etkin")).toBeInTheDocument();
      expect(setItemSpy).not.toHaveBeenCalled();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("admin kendi hesabını devre dışı bırakamaz", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Yönetici");
      await openUserAdmin(user);

      const self = userItem("Demo Yönetici");
      expect(within(self).getByText("(siz)")).toBeInTheDocument();
      expect(within(self).queryByRole("button")).not.toBeInTheDocument();
      expect(within(self).getByText(/kendi hesabınızı devre dışı bırakamazsınız/i)).toBeInTheDocument();
    });

    it("durum değişikliği hatası senaryosunda hata gösterir ve durumu korur", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Yönetici");
      await openUserAdmin(user);

      const panel = screen.getByRole("group", { name: /geliştirici demo paneli/i });
      await user.selectOptions(
        within(panel).getByLabelText("Durum değişikliği sonucu"),
        "Beklenmeyen hata",
      );
      await user.click(
        within(userItem("Örnek Kullanıcı 1")).getByRole("button", { name: /devre dışı bırak/i }),
      );
      await user.click(
        within(screen.getByRole("dialog")).getByRole("button", { name: "Devre dışı bırak" }),
      );
      expect(await screen.findByRole("alert")).toHaveTextContent(/değiştirilemedi/i);
      expect(within(userItem("Örnek Kullanıcı 1")).getByText("Etkin")).toBeInTheDocument();
    });

    it("boş liste ve yükleme hatası durumlarını gösterir", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Yönetici");
      await openUserAdmin(user);
      const panel = screen.getByRole("group", { name: /geliştirici demo paneli/i });

      await user.selectOptions(within(panel).getByLabelText("Liste yükleme sonucu"), "Boş liste");
      await user.click(screen.getByRole("button", { name: "Listeyi yenile" }));
      expect(await screen.findByText(/gösterilecek demo kullanıcısı yok/i)).toBeInTheDocument();

      await user.selectOptions(within(panel).getByLabelText("Liste yükleme sonucu"), "Yükleme hatası");
      await user.click(screen.getByRole("button", { name: "Listeyi yenile" }));
      expect(await screen.findByRole("alert")).toHaveTextContent(/yüklenemedi/i);
      expect(screen.queryByRole("list", { name: "Demo kullanıcıları" })).not.toBeInTheDocument();
    });

    it("arama ve durum filtresi yalnızca demo listesinde çalışır", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Yönetici");
      const list = await openUserAdmin(user);

      await user.type(screen.getByLabelText("Kullanıcı ara"), "kullanici-4");
      expect(within(list).getAllByRole("listitem")).toHaveLength(1);
      expect(userItem("Örnek Kullanıcı 4")).toBeInTheDocument();

      await user.clear(screen.getByLabelText("Kullanıcı ara"));
      await user.selectOptions(screen.getByLabelText("Hesap durumu"), "Pasif");
      expect(within(list).getAllByRole("listitem")).toHaveLength(1);

      await user.type(screen.getByLabelText("Kullanıcı ara"), "eşleşmeyen");
      expect(screen.getByText(/aramanızla eşleşen demo kullanıcısı yok/i)).toBeInTheDocument();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("yönetici ekranında API anahtarı, sağlayıcı veya analiz verisi yoktur", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Yönetici");

      // Admin kendi demo anahtarını kaydetse bile yönetici ekranına yansımaz.
      await user.click(screen.getByRole("link", { name: "API Anahtarlarım" }));
      const shodan = await screen.findByRole("article", { name: "Shodan" });
      await user.type(within(shodan).getByLabelText("Shodan API anahtarı"), FAKE_KEY);
      await user.click(within(shodan).getByRole("button", { name: "Anahtarı kaydet" }));
      await within(shodan).findByText("•••• abcd");

      await openUserAdmin(user);
      const main = screen.getByRole("main");
      expect(main).not.toHaveTextContent(FAKE_KEY);
      expect(main).not.toHaveTextContent("••••");
      expect(main).not.toHaveTextContent(/shodan|virustotal|abuseipdb|greynoise|otx|zerobounce/i);
      expect(main).not.toHaveTextContent(/risk skoru|ioc değeri|rapor id/i);
      expect(screen.queryByRole("article")).not.toBeInTheDocument();
    });

    it("rol değiştirme, yönetici atama veya hesap silme eylemi sunmaz", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Yönetici");
      await openUserAdmin(user);
      expect(
        screen.queryByRole("button", { name: /yönetici yap|rol|sil|parola|e-posta gönder/i }),
      ).not.toBeInTheDocument();
      expect(screen.queryByRole("combobox", { name: /rol/i })).not.toBeInTheDocument();
    });

    it("gerçek giriş ekranı AppShell içinde, değişmeden kalır", () => {
      renderApp("/login");
      expect(screen.getByTestId("login-username")).toBeInTheDocument();
      expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    });
  });
});

describe("mock yönetici kullanıcı servisi", () => {
  const admin: DemoAccount = { id: "demo-admin", displayName: "Demo Yönetici", role: "admin" };
  const analyst: DemoAccount = { id: "demo-analyst", displayName: "Demo Kullanıcı", role: "analyst" };

  function store(scenarios: Partial<{ list: "success" | "empty" | "error"; update: "success" | "error" }> = {}) {
    return createMockAdminUserStore({
      getScenarios: () => ({ list: "success", update: "success", ...scenarios }),
      delayMs: 0,
    });
  }

  it("yalnızca izin verilen alanları döndürür", async () => {
    const result = await store().forActor(admin).listUsers();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    for (const u of result.users) {
      expect(Object.keys(u).sort()).toEqual(
        ["accountStatus", "demoEmail", "displayName", "emailVerification", "id", "isSelf", "role"].sort(),
      );
      expect(u.demoEmail).toMatch(/@demo\.invalid$/);
    }
    expect(result.users.filter((u) => u.role === "admin")).toHaveLength(1);
  });

  it("analyst aktörünü reddeder", async () => {
    const service = store().forActor(analyst);
    expect(await service.listUsers()).toEqual({ ok: false, error: "forbidden" });
    expect(await service.setAccountStatus("demo-user-1", "disabled")).toEqual({
      ok: false,
      error: "forbidden",
    });
  });

  it("admin kendi hesabını veya bir yönetici hesabını değiştiremez", async () => {
    const service = store().forActor(admin);
    expect(await service.setAccountStatus("demo-admin", "disabled")).toEqual({
      ok: false,
      error: "self_action_forbidden",
    });
  });

  it("değişiklik yalnızca store belleğinde tutulur ve döndürülen nesne kopyadır", async () => {
    const s = store();
    const service = s.forActor(admin);
    const result = await service.setAccountStatus("demo-user-1", "disabled");
    expect(result).toMatchObject({ ok: true, user: { id: "demo-user-1", accountStatus: "disabled" } });
    if (result.ok) result.user.accountStatus = "active"; // dışarıdan mutasyon store'u etkilemez
    const listed = await service.listUsers();
    expect(listed.ok && listed.users.find((u) => u.id === "demo-user-1")?.accountStatus).toBe(
      "disabled",
    );
  });

  it("bilinmeyen kullanıcıyı reddeder", async () => {
    expect(await store().forActor(admin).setAccountStatus("yok", "disabled")).toEqual({
      ok: false,
      error: "not_found",
    });
  });
});
