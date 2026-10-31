/**
 * Demo prototipi (Aşama 2) — hesap akışları ve demo kabuğu testleri.
 *
 *  - Hesap ekranları yalnızca `VITE_PROTOTYPE_MODE` açıkken erişilebilir.
 *  - Demo sayfaları gerçek AppShell kenar çubuğunu ve backend göstergesini içermez.
 *  - Kayıt → e-posta kodu → demo giriş ve parola sıfırlama akışları,
 *    geliştirici demo panelindeki senaryolara göre doğru mesajları gösterir.
 *  - Parola ve kod web storage'a yazılmaz, loglanmaz; ağ isteği yapılmaz;
 *    gerçek token store değişmez.
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
import { DEMO_VERIFICATION_CODE } from "@/demo/demoAccountService";

const PASSWORD = "Demo-Parola-2026";
const ACCOUNT_PATHS = [
  "/demo/signup",
  "/demo/verify-email",
  "/demo/forgot-password",
  "/demo/reset-password",
];

function renderApp(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

async function fillSignup(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Görünen ad"), "Demo Analist");
  await user.type(screen.getByLabelText("E-posta"), "analist@example.com");
  await user.type(screen.getByLabelText("Parola"), PASSWORD);
  await user.type(screen.getByLabelText("Parola tekrarı"), PASSWORD);
  await user.click(screen.getByRole("button", { name: /hesap oluştur/i }));
}

async function chooseScenario(
  user: ReturnType<typeof userEvent.setup>,
  label: RegExp,
  optionText: string,
) {
  const panel = screen.getByRole("group", { name: /geliştirici demo paneli/i });
  await user.selectOptions(
    within(panel).getByLabelText(label),
    within(panel).getByRole("option", { name: optionText }),
  );
}

describe("demo hesap akışları", () => {
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

  describe("VITE_PROTOTYPE_MODE kapalıyken", () => {
    it.each(ACCOUNT_PATHS)("%s mevcut 404 sayfasına (AppShell içinde) düşer", (path) => {
      renderApp(path);
      expect(screen.getByText("404")).toBeInTheDocument();
      expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
      expect(screen.queryByText(/demo prototipi/i)).not.toBeInTheDocument();
    });
  });

  describe("VITE_PROTOTYPE_MODE açıkken", () => {
    beforeEach(() => {
      flags.prototypeMode = true;
    });

    it.each(["/demo/login", ...ACCOUNT_PATHS])(
      "%s demo kabuğunda açılır; gerçek kenar çubuğu ve backend göstergesi yoktur",
      (path) => {
        renderApp(path);
        expect(
          screen.getByRole("region", { name: /demo prototipi/i }),
        ).toBeInTheDocument();
        expect(screen.queryByRole("navigation", { name: "Primary" })).not.toBeInTheDocument();
        expect(screen.queryByRole("status", { name: /backend/i })).not.toBeInTheDocument();
        expect(screen.queryByText(/threat intelligence konsolu/i)).not.toBeInTheDocument();
        // AppShell'in Topbar'ı sağlık kontrolü yapardı; demo kabuğu yapmaz.
        expect(fetchMock).not.toHaveBeenCalled();
      },
    );

    it("gerçek uygulama rotaları AppShell içinde kalır", () => {
      renderApp("/olmayan-sayfa");
      expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
      expect(screen.getByText("404")).toBeInTheDocument();
    });

    it("demo girişinden hesap oluşturma ve parola sıfırlama ekranlarına geçilir", async () => {
      const user = userEvent.setup();
      renderApp("/demo/login");
      await user.click(screen.getByRole("link", { name: /hesap oluştur/i }));
      expect(
        await screen.findByRole("heading", { name: /hesap oluştur/i }),
      ).toBeInTheDocument();
      await user.click(screen.getByRole("link", { name: /demo girişine dön/i }));
      await user.click(screen.getByRole("link", { name: /parolamı unuttum/i }));
      expect(
        await screen.findByRole("heading", { name: /parolamı unuttum/i }),
      ).toBeInTheDocument();
    });

    describe("hesap oluşturma", () => {
      it("boş formda erişilebilir alan hataları gösterir ve ilk hatalı alana odaklanır", async () => {
        const user = userEvent.setup();
        renderApp("/demo/signup");
        await user.click(screen.getByRole("button", { name: /hesap oluştur/i }));

        const name = screen.getByLabelText("Görünen ad");
        expect(name).toHaveAttribute("aria-invalid", "true");
        expect(name).toHaveAccessibleDescription(/görünen ad gerekli/i);
        expect(name).toHaveFocus();
        expect(screen.getByLabelText("E-posta")).toHaveAccessibleDescription(
          /e-posta gerekli/i,
        );
      });

      it("hatalı e-posta biçimi, zayıf ve eşleşmeyen parolayı bildirir", async () => {
        const user = userEvent.setup();
        renderApp("/demo/signup");
        await user.type(screen.getByLabelText("Görünen ad"), "Demo");
        await user.type(screen.getByLabelText("E-posta"), "gecersiz-adres");
        await user.type(screen.getByLabelText("Parola"), "kisa");
        await user.type(screen.getByLabelText("Parola tekrarı"), "farkli");
        await user.click(screen.getByRole("button", { name: /hesap oluştur/i }));

        expect(screen.getByLabelText("E-posta")).toHaveAccessibleDescription(
          /geçerli bir e-posta/i,
        );
        expect(screen.getByLabelText("Parola")).toHaveAttribute("aria-invalid", "true");
        expect(screen.getByLabelText("Parola tekrarı")).toHaveAccessibleDescription(
          /parolalar eşleşmiyor/i,
        );
      });

      it("parola gereksinimlerini yazarken günceller", async () => {
        const user = userEvent.setup();
        renderApp("/demo/signup");
        const list = screen.getByRole("list", { name: /parola gereksinimleri/i });
        expect(within(list).getByText(/en az 12 karakter/i)).toHaveTextContent(
          /\(karşılanmadı\)/i,
        );
        await user.type(screen.getByLabelText("Parola"), PASSWORD);
        expect(within(list).getByText(/en az 12 karakter/i)).toHaveTextContent(
          /\(karşılandı\)/i,
        );
      });

      it("başarılı demo kaydından sonra maskeli adresle doğrulama ekranına geçer", async () => {
        const user = userEvent.setup();
        renderApp("/demo/signup");
        await fillSignup(user);

        expect(
          await screen.findByRole("heading", { name: /e-posta doğrulama/i }),
        ).toBeInTheDocument();
        expect(screen.getByText("a***@example.com")).toBeInTheDocument();
        expect(screen.queryByText("analist@example.com")).not.toBeInTheDocument();
        expect(screen.getAllByText(/gerçek e-posta gönderilmedi/i).length).toBeGreaterThan(0);
      });
    });

    describe("e-posta kodu doğrulama", () => {
      it("kayıt yokken boş durumu gösterir", () => {
        renderApp("/demo/verify-email");
        expect(screen.getByText(/doğrulanacak bir demo kaydı yok/i)).toBeInTheDocument();
      });

      it("hatalı kodu reddeder ve kodu ekranda tekrar göstermez", async () => {
        const user = userEvent.setup();
        renderApp("/demo/signup");
        await fillSignup(user);
        await screen.findByRole("heading", { name: /e-posta doğrulama/i });

        await user.type(screen.getByLabelText("Doğrulama kodu"), "999999");
        await user.click(screen.getByRole("button", { name: /kodu doğrula/i }));

        expect(await screen.findByRole("alert")).toHaveTextContent(/kod hatalı/i);
        expect(screen.getByRole("alert")).not.toHaveTextContent("999999");
      });

      it("6 haneli olmayan kodu istemci tarafında reddeder", async () => {
        const user = userEvent.setup();
        renderApp("/demo/signup");
        await fillSignup(user);
        await screen.findByRole("heading", { name: /e-posta doğrulama/i });

        await user.type(screen.getByLabelText("Doğrulama kodu"), "12");
        await user.click(screen.getByRole("button", { name: /kodu doğrula/i }));
        expect(screen.getByLabelText("Doğrulama kodu")).toHaveAccessibleDescription(
          /6 haneli/i,
        );
      });

      it("süresi dolmuş kod senaryosunu gösterir", async () => {
        const user = userEvent.setup();
        renderApp("/demo/signup");
        await fillSignup(user);
        await screen.findByRole("heading", { name: /e-posta doğrulama/i });

        await chooseScenario(user, /kod doğrulama sonucu/i, "Süresi dolmuş kod");
        await user.type(screen.getByLabelText("Doğrulama kodu"), DEMO_VERIFICATION_CODE);
        await user.click(screen.getByRole("button", { name: /kodu doğrula/i }));

        expect(await screen.findByRole("alert")).toHaveTextContent(/süresi dolmuş/i);
      });

      it("tekrar gönderme sonrası geri sayım başlatır; bekleme senaryosunu gösterir", async () => {
        const user = userEvent.setup();
        renderApp("/demo/signup");
        await fillSignup(user);
        await screen.findByRole("heading", { name: /e-posta doğrulama/i });

        await user.click(screen.getByRole("button", { name: /kodu tekrar gönder/i }));
        expect(
          await screen.findByRole("button", { name: /tekrar gönder \(\d+ sn\)/i }),
        ).toBeDisabled();
        expect(screen.getByRole("status", { name: /tekrar gönderme durumu/i })).toHaveTextContent(
          /demo: gerçek e-posta gönderilmedi/i,
        );
      });

      it("bekleme süresi senaryosunda bekleme mesajı gösterir", async () => {
        const user = userEvent.setup();
        renderApp("/demo/signup");
        await fillSignup(user);
        await screen.findByRole("heading", { name: /e-posta doğrulama/i });

        await chooseScenario(user, /tekrar gönderme sonucu/i, "Bekleme süresi dolmadı");
        await user.click(screen.getByRole("button", { name: /kodu tekrar gönder/i }));
        expect(await screen.findByRole("alert")).toHaveTextContent(/çok sık/i);
        expect(
          screen.getByRole("button", { name: /tekrar gönder \(\d+ sn\)/i }),
        ).toBeDisabled();
      });

      it("geçerli demo kodu ile demo girişine yönlendirir; parola/kod saklanmaz", async () => {
        const user = userEvent.setup();
        setAccessToken("real-session-token");
        renderApp("/demo/signup");
        await fillSignup(user);
        await screen.findByRole("heading", { name: /e-posta doğrulama/i });

        await user.type(screen.getByLabelText("Doğrulama kodu"), DEMO_VERIFICATION_CODE);
        await user.click(screen.getByRole("button", { name: /kodu doğrula/i }));

        expect(
          await screen.findByRole("heading", { name: /demo girişi/i }),
        ).toBeInTheDocument();
        expect(screen.getByRole("status", { name: /demo bildirimi/i })).toHaveTextContent(
          /gerçek bir hesap oluşturulmadı/i,
        );

        expect(getAccessToken()).toBe("real-session-token");
        expect(fetchMock).not.toHaveBeenCalled();
        expect(setItemSpy).not.toHaveBeenCalled();
        const logged = consoleSpies.flatMap((spy) => spy.mock.calls.flat().map(String));
        expect(logged.join(" ")).not.toContain(PASSWORD);
        expect(logged.join(" ")).not.toContain(DEMO_VERIFICATION_CODE);
      });
    });

    describe("parola sıfırlama", () => {
      it("e-posta biçimini doğrular", async () => {
        const user = userEvent.setup();
        renderApp("/demo/forgot-password");
        await user.click(screen.getByRole("button", { name: /sıfırlama bağlantısı iste/i }));
        expect(screen.getByLabelText("E-posta")).toHaveAccessibleDescription(
          /e-posta gerekli/i,
        );
      });

      it("demo başarı durumunu hesap varlığını açıklamadan gösterir", async () => {
        const user = userEvent.setup();
        renderApp("/demo/forgot-password");
        await user.type(screen.getByLabelText("E-posta"), "biri@example.com");
        await user.click(screen.getByRole("button", { name: /sıfırlama bağlantısı iste/i }));

        const status = await screen.findByRole("status", { name: /sıfırlama talebi/i });
        expect(status).toHaveTextContent(/gerçek e-posta gönderilmedi/i);
        expect(status).toHaveTextContent(/kayıtlıysa/i);
        expect(
          screen.getByRole("link", { name: /demo sıfırlama ekranını aç/i }),
        ).toBeInTheDocument();
      });

      it("hata senaryosunda hata mesajı gösterir", async () => {
        const user = userEvent.setup();
        renderApp("/demo/forgot-password");
        await chooseScenario(user, /sıfırlama talebi sonucu/i, "Servis hatası");
        await user.type(screen.getByLabelText("E-posta"), "biri@example.com");
        await user.click(screen.getByRole("button", { name: /sıfırlama bağlantısı iste/i }));
        expect(await screen.findByRole("alert")).toHaveTextContent(/şu anda işlenemedi/i);
      });

      it("yeni parola alanlarını doğrular", async () => {
        const user = userEvent.setup();
        renderApp("/demo/reset-password");
        await user.type(screen.getByLabelText("Yeni parola"), PASSWORD);
        await user.type(screen.getByLabelText("Yeni parola tekrarı"), "Baska-Parola-2026");
        await user.click(screen.getByRole("button", { name: /parolayı güncelle/i }));
        expect(screen.getByLabelText("Yeni parola tekrarı")).toHaveAccessibleDescription(
          /parolalar eşleşmiyor/i,
        );
      });

      it("süresi dolmuş bağlantı senaryosunda hata gösterir", async () => {
        const user = userEvent.setup();
        renderApp("/demo/reset-password");
        await chooseScenario(user, /yeni parola sonucu/i, "Bağlantının süresi dolmuş");
        await user.type(screen.getByLabelText("Yeni parola"), PASSWORD);
        await user.type(screen.getByLabelText("Yeni parola tekrarı"), PASSWORD);
        await user.click(screen.getByRole("button", { name: /parolayı güncelle/i }));
        expect(await screen.findByRole("alert")).toHaveTextContent(/süresi dolmuş/i);
      });

      it("başarılı demo sıfırlamadan sonra demo girişine döner; parola saklanmaz", async () => {
        const user = userEvent.setup();
        renderApp("/demo/reset-password");
        await user.type(screen.getByLabelText("Yeni parola"), PASSWORD);
        await user.type(screen.getByLabelText("Yeni parola tekrarı"), PASSWORD);
        await user.click(screen.getByRole("button", { name: /parolayı güncelle/i }));

        expect(
          await screen.findByRole("heading", { name: /demo girişi/i }),
        ).toBeInTheDocument();
        expect(screen.getByRole("status", { name: /demo bildirimi/i })).toHaveTextContent(
          /hiçbir parola değiştirilmedi/i,
        );
        expect(setItemSpy).not.toHaveBeenCalled();
        expect(fetchMock).not.toHaveBeenCalled();
      });
    });
  });
});
