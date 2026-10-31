/**
 * Demo prototipi (Aşama 3) — "API Anahtarlarım" ve sağlayıcı rehberleri.
 *
 *  - Sayfa yalnızca `VITE_PROTOTYPE_MODE` açıkken ve demo oturumuyla erişilir.
 *  - Gerçek, sunucu genelindeki "Provider'lar" sayfasından ayrıdır.
 *  - Ham anahtar web storage'a, DOM'a, loglara veya mesajlara yazılmaz;
 *    mock servis ham değeri saklamaz/döndürmez ve "doğrulandı" üretmez.
 *  - Anahtar metadata'sı demo oturumları arasında paylaşılmaz.
 *  - Shodan rehberi resmi bağlantıları, yazılı adımları ve açık görsel
 *    yer tutucularını içerir.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";

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
import { clearAccessToken, getAccessToken, setAccessToken } from "@/auth/tokenStore";
import { createMockApiKeyStore } from "@/demo/demoApiKeyService";
import type { ApiKeyScenarios, VerificationScenario } from "@/demo/demoApiKeyService";
import { DEMO_PROVIDERS } from "@/demo/demoProviders";

// Açıkça sahte test değerleri — gerçek bir sağlayıcı anahtarı değildir.
const FAKE_KEY = "demo-sahte-anahtar-0000abcd";
const OTHER_FAKE_KEY = "demo-sahte-anahtar-1111wxyz";

type User = ReturnType<typeof userEvent.setup>;

function renderApp(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

async function loginAs(user: User, role: "Kullanıcı" | "Yönetici") {
  await user.click(screen.getByRole("radio", { name: new RegExp(`^${role}`, "i") }));
  await user.click(screen.getByRole("button", { name: /demo alanına gir/i }));
  await screen.findByRole("heading", { name: /demo kontrol paneli/i });
}

async function openApiKeys(user: User) {
  await user.click(screen.getByRole("link", { name: "API Anahtarlarım" }));
  await screen.findByRole("heading", { name: "API Anahtarlarım", level: 1 });
  // Kartlar yüklenene kadar bekle.
  return screen.findByRole("article", { name: "Shodan" });
}

function card(name: string) {
  return screen.getByRole("article", { name });
}

async function saveKey(user: User, providerName: string, value: string) {
  const c = card(providerName);
  await user.type(within(c).getByLabelText(`${providerName} API anahtarı`), value);
  await user.click(within(c).getByRole("button", { name: /anahtarı (kaydet|değiştir)/i }));
  await within(c).findByText(/kayıtlı · doğrulanmadı/i);
}

describe("demo API anahtarları", () => {
  const fetchMock = vi.fn();
  let setItemSpy: ReturnType<typeof vi.spyOn>;
  let consoleSpies: ReturnType<typeof vi.spyOn>[];

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockRejectedValue(new Error("network disabled in tests"));
    vi.stubGlobal("fetch", fetchMock);
    setItemSpy = vi.spyOn(Storage.prototype, "setItem");
    consoleSpies = (["log", "info", "warn", "error", "debug"] as const).map(
      (method) => vi.spyOn(console, method),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    clearAccessToken();
    flags.prototypeMode = false;
  });

  function loggedText(): string {
    return consoleSpies.flatMap((spy) => spy.mock.calls.flat().map(String)).join(" ");
  }

  describe("VITE_PROTOTYPE_MODE kapalıyken", () => {
    it.each(["/demo/api-keys", "/demo/api-keys/guides/shodan"])(
      "%s mevcut 404 sayfasına düşer",
      (path) => {
        renderApp(path);
        expect(screen.getByText("404")).toBeInTheDocument();
        expect(screen.queryByText(/api anahtarlarım/i)).not.toBeInTheDocument();
      },
    );
  });

  describe("VITE_PROTOTYPE_MODE açıkken", () => {
    beforeEach(() => {
      flags.prototypeMode = true;
    });

    it("demo oturumu yokken demo girişine yönlendirir", () => {
      renderApp("/demo/api-keys");
      expect(screen.getByRole("heading", { name: /demo girişi/i })).toBeInTheDocument();
    });

    it("doğrulanmış altı sağlayıcı için kart gösterir; gerçek Provider'lar sayfasından ayrıdır", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Kullanıcı");
      await openApiKeys(user);

      for (const name of [
        "VirusTotal",
        "AbuseIPDB",
        "Shodan",
        "AlienVault OTX",
        "GreyNoise",
        "ZeroBounce",
      ]) {
        expect(within(card(name)).getByText("Anahtar eklenmemiş")).toBeInTheDocument();
      }
      expect(screen.getAllByRole("article")).toHaveLength(6);
      expect(screen.getByText(/sunucu genelindeki/i)).toBeInTheDocument();
      expect(screen.queryByRole("navigation", { name: "Primary" })).not.toBeInTheDocument();
      expect(screen.queryByRole("heading", { name: "Provider'lar" })).not.toBeInTheDocument();
      // Gerçek Provider'lar sayfası backend'den veri çekerdi; demo sayfası çekmez.
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("anahtarı kaydeder, alanı temizler ve yalnızca maskeli metadata gösterir", async () => {
      const user = userEvent.setup();
      setAccessToken("real-session-token");
      renderApp("/demo/login");
      await loginAs(user, "Kullanıcı");
      await openApiKeys(user);

      await saveKey(user, "Shodan", FAKE_KEY);

      const shodan = card("Shodan");
      expect(within(shodan).getByLabelText("Shodan API anahtarı")).toHaveValue("");
      expect(within(shodan).getByText("•••• abcd")).toBeInTheDocument();
      expect(within(shodan).getByRole("status")).toHaveTextContent(/demo anahtarı kaydedildi/i);
      expect(within(shodan).getByRole("status")).toHaveTextContent(/doğrulanmadı/i);
      expect(within(shodan).getByRole("button", { name: "Anahtarı değiştir" })).toBeInTheDocument();

      expect(document.body.innerHTML).not.toContain(FAKE_KEY);
      expect(setItemSpy).not.toHaveBeenCalled();
      expect(fetchMock).not.toHaveBeenCalled();
      expect(loggedText()).not.toContain(FAKE_KEY);
      expect(getAccessToken()).toBe("real-session-token");
    });

    it("boş veya boşluk içeren anahtarı değeri göstermeden reddeder", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Kullanıcı");
      await openApiKeys(user);
      const shodan = card("Shodan");
      const input = within(shodan).getByLabelText("Shodan API anahtarı");

      await user.click(within(shodan).getByRole("button", { name: "Anahtarı kaydet" }));
      expect(input).toHaveAccessibleDescription(/anahtar gerekli/i);
      expect(input).toHaveFocus();

      await user.type(input, "abc def-gizli");
      await user.click(within(shodan).getByRole("button", { name: "Anahtarı kaydet" }));
      expect(input).toHaveAccessibleDescription(/boşluk/i);
      expect(document.body.textContent).not.toContain("def-gizli");
    });

    it("göster/gizle düğmesi klavye ile çalışır", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Kullanıcı");
      await openApiKeys(user);
      const shodan = card("Shodan");
      const input = within(shodan).getByLabelText("Shodan API anahtarı");
      expect(input).toHaveAttribute("type", "password");
      expect(input).not.toHaveAttribute("name");

      await user.click(input);
      await user.tab();
      const toggle = within(shodan).getByRole("button", { name: "Anahtarı göster" });
      expect(toggle).toHaveFocus();
      await user.keyboard("{Enter}");
      expect(input).toHaveAttribute("type", "text");
      expect(within(shodan).getByRole("button", { name: "Anahtarı gizle" })).toHaveFocus();
      await user.keyboard(" ");
      expect(input).toHaveAttribute("type", "password");
    });

    it("demo bağlantı denemesi gerçek doğrulama sonucu üretmez", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Kullanıcı");
      await openApiKeys(user);
      await saveKey(user, "Shodan", FAKE_KEY);

      const shodan = card("Shodan");
      await user.click(within(shodan).getByRole("button", { name: /bağlantıyı dene/i }));
      expect(
        await within(shodan).findByText(/demo: sağlayıcıya bağlanılmadı, anahtar doğrulanmadı/i),
      ).toBeInTheDocument();
      expect(screen.queryByText(/^doğrulandı$/i)).not.toBeInTheDocument();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("hata senaryosu düzeltme yolu sunar ve diğer sağlayıcıları etkilemez", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Kullanıcı");
      await openApiKeys(user);
      await saveKey(user, "Shodan", FAKE_KEY);
      await saveKey(user, "VirusTotal", OTHER_FAKE_KEY);

      const panel = screen.getByRole("group", { name: /geliştirici demo paneli/i });
      await user.selectOptions(within(panel).getByLabelText("Sağlayıcı"), "Shodan");
      await user.selectOptions(
        within(panel).getByLabelText("Bağlantı denemesi sonucu"),
        "Anahtar geçersiz",
      );

      const shodan = card("Shodan");
      await user.click(within(shodan).getByRole("button", { name: /bağlantıyı dene/i }));
      const alert = await within(shodan).findByRole("alert");
      expect(alert).toHaveTextContent(/anahtarı kabul etmedi/i);
      expect(alert).toHaveTextContent(/diğer sağlayıcılar/i);
      expect(alert).toHaveTextContent(/demo senaryosu/i);
      expect(alert).not.toHaveTextContent(FAKE_KEY);
      expect(within(alert).getByRole("link", { name: /api anahtarı nasıl alınır/i })).toHaveAttribute(
        "href",
        "/demo/api-keys/guides/shodan",
      );

      await user.click(within(alert).getByRole("button", { name: "Anahtarı düzenle" }));
      expect(within(shodan).getByLabelText("Shodan API anahtarı")).toHaveFocus();

      // VirusTotal kartı etkilenmez.
      expect(within(card("VirusTotal")).getByText(/kayıtlı · doğrulanmadı/i)).toBeInTheDocument();
      expect(within(card("VirusTotal")).queryByRole("alert")).not.toBeInTheDocument();
      expect(screen.getByText(/1 sağlayıcıda sorun var/i)).toBeInTheDocument();
    });

    it.each<[string, RegExp]>([
      ["Erişim/izin yok", /api erişimi/i],
      ["Kota veya hız sınırı", /kota veya hız sınırına/i],
      ["Sağlayıcıya ulaşılamıyor", /ulaşılamıyor/i],
      ["Beklenmeyen hata", /beklenmeyen bir hata/i],
    ])("%s senaryosu anlaşılır mesaj gösterir", async (option, message) => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Kullanıcı");
      await openApiKeys(user);
      await saveKey(user, "Shodan", FAKE_KEY);

      const panel = screen.getByRole("group", { name: /geliştirici demo paneli/i });
      await user.selectOptions(within(panel).getByLabelText("Bağlantı denemesi sonucu"), option);
      await user.click(within(card("Shodan")).getByRole("button", { name: /bağlantıyı dene/i }));
      expect(await within(card("Shodan")).findByRole("alert")).toHaveTextContent(message);
    });

    it("kaydetme hatası senaryosunda anahtarı kaydetmez ve değeri göstermez", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Kullanıcı");
      await openApiKeys(user);

      const panel = screen.getByRole("group", { name: /geliştirici demo paneli/i });
      await user.selectOptions(within(panel).getByLabelText("Kaydetme sonucu"), "Beklenmeyen hata");
      const shodan = card("Shodan");
      await user.type(within(shodan).getByLabelText("Shodan API anahtarı"), FAKE_KEY);
      await user.click(within(shodan).getByRole("button", { name: "Anahtarı kaydet" }));

      expect(await within(shodan).findByRole("alert")).toHaveTextContent(/kaydedilemedi/i);
      expect(within(shodan).getByText("Anahtar eklenmemiş")).toBeInTheDocument();
      expect(screen.getByRole("alert")).not.toHaveTextContent(FAKE_KEY);
    });

    it("silmeden önce onay ister; Escape iptal eder ve odağı geri verir", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Kullanıcı");
      await openApiKeys(user);
      await saveKey(user, "Shodan", FAKE_KEY);

      const deleteButton = within(card("Shodan")).getByRole("button", { name: "Anahtarı sil" });
      await user.click(deleteButton);
      const dialog = screen.getByRole("dialog", { name: /shodan anahtarı silinsin mi/i });
      expect(within(dialog).getByRole("button", { name: "Vazgeç" })).toHaveFocus();

      await user.keyboard("{Escape}");
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(deleteButton).toHaveFocus();
      expect(within(card("Shodan")).getByText("•••• abcd")).toBeInTheDocument();

      await user.click(deleteButton);
      await user.click(
        within(screen.getByRole("dialog")).getByRole("button", { name: "Anahtarı sil" }),
      );
      expect(await within(card("Shodan")).findByText("Anahtar eklenmemiş")).toBeInTheDocument();
      expect(within(card("Shodan")).getByRole("status")).toHaveTextContent(/silindi/i);
    });

    it("anahtar metadata'sı demo oturumları arasında paylaşılmaz", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await loginAs(user, "Yönetici");
      await openApiKeys(user);
      expect(
        screen.getByText(/başka kullanıcıların anahtarlarını görme yetkisi vermez/i),
      ).toBeInTheDocument();
      await saveKey(user, "Shodan", FAKE_KEY);

      await user.click(screen.getByRole("button", { name: /demo oturumunu kapat/i }));
      await loginAs(user, "Kullanıcı");
      await openApiKeys(user);
      expect(within(card("Shodan")).getByText("Anahtar eklenmemiş")).toBeInTheDocument();

      // Aynı rolle yeniden giriş de yeni, boş bir demo oturumudur.
      await user.click(screen.getByRole("button", { name: /demo oturumunu kapat/i }));
      await loginAs(user, "Yönetici");
      await openApiKeys(user);
      expect(within(card("Shodan")).getByText("Anahtar eklenmemiş")).toBeInTheDocument();
    });

    describe("rehberler", () => {
      it("Shodan rehberi resmi bağlantıları, yazılı adımları ve görsel yer tutucularını gösterir", async () => {
        const user = userEvent.setup();
        renderApp("/demo/login");
        await loginAs(user, "Kullanıcı");
        await openApiKeys(user);
        await user.click(
          within(card("Shodan")).getByRole("link", { name: /api anahtarı nasıl alınır/i }),
        );

        expect(
          await screen.findByRole("heading", { name: /shodan api anahtarı nasıl alınır/i }),
        ).toBeInTheDocument();

        const account = screen.getByRole("link", { name: /shodan hesap sayfası/i });
        expect(account).toHaveAttribute("href", "https://account.shodan.io");
        expect(account).toHaveAttribute("target", "_blank");
        expect(account).toHaveAttribute("rel", expect.stringContaining("noopener"));
        expect(account).toHaveAttribute("rel", expect.stringContaining("noreferrer"));
        expect(screen.getByRole("link", { name: /shodan resmî yardım sayfası/i })).toHaveAttribute(
          "href",
          "https://help.shodan.io/developer-fundamentals/looking-up-ip-info",
        );

        const steps = screen.getByRole("list", { name: /adımlar/i });
        expect(within(steps).getAllByRole("listitem")).toHaveLength(7);
        expect(within(steps).getByText(/api key alanını bul/i)).toBeInTheDocument();
        expect(screen.getAllByText(/görsel yer tutucusu/i)).toHaveLength(7);
        expect(document.querySelector("img")).toBeNull();
      });

      it("rehberden dönünce Shodan anahtar alanına odaklanır", async () => {
        const user = userEvent.setup();
        renderApp("/demo/login");
        await loginAs(user, "Kullanıcı");
        await openApiKeys(user);
        await user.click(
          within(card("Shodan")).getByRole("link", { name: /api anahtarı nasıl alınır/i }),
        );
        await user.click(await screen.findByRole("link", { name: /shodan kartına dön/i }));
        await screen.findByRole("article", { name: "Shodan" });
        expect(within(card("Shodan")).getByLabelText("Shodan API anahtarı")).toHaveFocus();
      });

      it("diğer sağlayıcılarda adım uydurmaz; resmî dokümantasyon ve yer tutucu gösterir", async () => {
        const user = userEvent.setup();
        renderApp("/demo/login");
        await loginAs(user, "Kullanıcı");
        await openApiKeys(user);
        await user.click(
          within(card("VirusTotal")).getByRole("link", { name: /api anahtarı nasıl alınır/i }),
        );

        expect(
          await screen.findByRole("heading", { name: /virustotal api anahtarı nasıl alınır/i }),
        ).toBeInTheDocument();
        expect(screen.getByRole("link", { name: /resmî api dokümantasyonu/i })).toHaveAttribute(
          "href",
          "https://developers.virustotal.com/reference/overview",
        );
        expect(screen.getByText(/henüz yazılmadı/i)).toBeInTheDocument();
        expect(screen.queryByRole("list", { name: /adımlar/i })).not.toBeInTheDocument();
      });

    });

    it("gerçek Provider'lar sayfası AppShell içinde, değişmeden kalır", async () => {
      renderApp("/providers");
      expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
      expect(screen.getByRole("heading", { name: "Provider'lar" })).toBeInTheDocument();
      expect(screen.queryByText(/demo prototipi/i)).not.toBeInTheDocument();
    });
  });
});

describe("mock API anahtarı servisi", () => {
  const allScenarios: VerificationScenario[] = [
    "not_verified",
    "invalid",
    "permission_denied",
    "rate_limited",
    "provider_unreachable",
    "unexpected_error",
  ];

  function storeWith(scenarios: Partial<ApiKeyScenarios> = {}) {
    return createMockApiKeyStore({
      getScenarios: () => ({ verify: "not_verified", save: "saved", ...scenarios }),
      delayMs: 0,
    });
  }

  it("altı doğrulanmış sağlayıcıyı tanımlar", () => {
    expect(DEMO_PROVIDERS.map((p) => p.id)).toEqual([
      "virustotal",
      "abuseipdb",
      "shodan",
      "otx",
      "greynoise",
      "zerobounce",
    ]);
  });

  it("ham anahtarı saklamaz ve hiçbir sonuçta döndürmez", async () => {
    const service = storeWith().forOwner("owner-a");
    const saved = await service.saveKey("shodan", FAKE_KEY);
    const listed = await service.listKeys();
    const checked = await service.checkKey("shodan");

    for (const result of [saved, listed, checked]) {
      expect(JSON.stringify(result)).not.toContain(FAKE_KEY);
      expect(JSON.stringify(result)).not.toContain("0000");
    }
    expect(saved).toMatchObject({ ok: true, key: { last4: "abcd", status: "saved_unverified" } });
  });

  it("kısa anahtarlarda son karakterleri de göstermez", async () => {
    const service = storeWith().forOwner("owner-a");
    const saved = await service.saveKey("shodan", "kisa1234");
    expect(saved).toMatchObject({ ok: true, key: { last4: null } });
  });

  it("sahipler arasında metadata paylaşmaz ve sahip silinince temizler", async () => {
    const store = storeWith();
    await store.forOwner("owner-a").saveKey("shodan", FAKE_KEY);

    const otherKeys = await store.forOwner("owner-b").listKeys();
    expect(otherKeys.find((k) => k.providerId === "shodan")?.status).toBe("not_configured");

    store.clearOwner("owner-a");
    const cleared = await store.forOwner("owner-a").listKeys();
    expect(cleared.every((k) => k.status === "not_configured")).toBe(true);
  });

  it.each(allScenarios)("'%s' senaryosu hiçbir zaman 'verified' üretmez", async (verify) => {
    const service = storeWith({ verify }).forOwner("owner-a");
    await service.saveKey("shodan", FAKE_KEY);
    const result = await service.checkKey("shodan");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.key.status).not.toBe("verified");
      expect(result.key.simulated).toBe(true);
    }
  });

  it("anahtar yokken bağlantı denemesini reddeder", async () => {
    const service = storeWith().forOwner("owner-a");
    expect(await service.checkKey("shodan")).toEqual({ ok: false, error: "not_configured" });
  });
});
