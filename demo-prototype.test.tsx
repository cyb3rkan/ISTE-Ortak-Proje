/**
 * Demo prototipi (Aşama 1) testleri.
 *
 *  - `VITE_PROTOTYPE_MODE` kapalıyken /demo rotaları mevcut 404 davranışına düşer.
 *  - Demo oturumu gerçek AuthProvider / token store'dan bağımsızdır.
 *  - Demo çıkışı gerçek oturumu (in-memory access token) etkilemez.
 *  - Demo akışı ağ isteği yapmaz ve web storage'a yazmaz.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";

// `config.prototypeMode` her testte ayrı ayarlanabilsin diye değiştirilebilir bayrak.
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
import { AppRoutes } from "@/routes";
import { clearAccessToken, getAccessToken, setAccessToken } from "@/auth/tokenStore";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("demo prototipi", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    // Bayrak kapalıyken 404, AppShell içinde açılır ve Topbar sağlık kontrolü yapar.
    fetchMock.mockRejectedValue(new Error("network disabled in tests"));
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    clearAccessToken();
    flags.prototypeMode = false;
  });

  describe("VITE_PROTOTYPE_MODE kapalıyken", () => {
    it.each(["/demo", "/demo/login", "/demo/dashboard"])(
      "%s mevcut 404 sayfasına düşer",
      (path) => {
        renderAt(path);
        expect(screen.getByText("404")).toBeInTheDocument();
        expect(screen.queryByText(/demo prototipi/i)).not.toBeInTheDocument();
      },
    );
  });

  describe("VITE_PROTOTYPE_MODE açıkken", () => {
    beforeEach(() => {
      flags.prototypeMode = true;
    });

    it("demo girişini görünür bir prototip etiketiyle gösterir", () => {
      renderAt("/demo/login");
      expect(
        screen.getByRole("region", { name: /demo prototipi/i }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("heading", { name: /demo girişi/i }),
      ).toBeInTheDocument();
      // Gerçek kimlik bilgisi alanı yoktur.
      expect(screen.queryByLabelText(/parola/i)).not.toBeInTheDocument();
      expect(screen.queryByLabelText(/e-posta/i)).not.toBeInTheDocument();
    });

    it("oturum yokken /demo ve /demo/dashboard demo girişine yönlendirir", () => {
      renderAt("/demo/dashboard");
      expect(
        screen.getByRole("heading", { name: /demo girişi/i }),
      ).toBeInTheDocument();
    });

    it("varsayılan rol analyst ('Kullanıcı') olarak seçilidir", () => {
      renderAt("/demo/login");
      expect(screen.getByRole("radio", { name: /kullanıcı/i })).toBeChecked();
      expect(screen.getByRole("radio", { name: /yönetici/i })).not.toBeChecked();
    });

    it.each([
      { option: /yönetici/i, roleLabel: "Yönetici" },
      { option: /kullanıcı/i, roleLabel: "Kullanıcı" },
    ])(
      "$roleLabel rolüyle girişten sonra /demo/dashboard açılır",
      async ({ option, roleLabel }) => {
        const user = userEvent.setup();
        renderAt("/demo/login");

        await user.click(screen.getByRole("radio", { name: option }));
        await user.click(screen.getByRole("button", { name: /demo alanına gir/i }));

        expect(
          await screen.findByRole("heading", { name: /demo kontrol paneli/i }),
        ).toBeInTheDocument();
        expect(screen.getByTestId("demo-session-role")).toHaveTextContent(roleLabel);
      },
    );

    it("demo giriş/çıkışı gerçek token store'a, ağa ve web storage'a dokunmaz", async () => {
      const user = userEvent.setup();
      const setItemSpy = vi.spyOn(Storage.prototype, "setItem");
      // Gerçek bir oturum varmış gibi in-memory access token yerleştir.
      setAccessToken("real-session-token");

      renderAt("/demo/login");
      await user.click(screen.getByRole("radio", { name: /yönetici/i }));
      await user.click(screen.getByRole("button", { name: /demo alanına gir/i }));
      await screen.findByRole("heading", { name: /demo kontrol paneli/i });
      expect(getAccessToken()).toBe("real-session-token");

      await user.click(
        screen.getAllByRole("button", { name: /demo oturumunu kapat/i })[0],
      );

      expect(
        await screen.findByRole("heading", { name: /demo girişi/i }),
      ).toBeInTheDocument();
      expect(getAccessToken()).toBe("real-session-token");
      expect(fetchMock).not.toHaveBeenCalled();
      expect(setItemSpy).not.toHaveBeenCalled();
    });

    it("demo alanı gerçek AuthProvider olmadan çalışır", async () => {
      // AppRoutes burada AuthProvider olmadan render edilir; demo alanı
      // useAuth() çağırsaydı bu test hata fırlatırdı.
      const user = userEvent.setup();
      render(
        <MemoryRouter initialEntries={["/demo/login"]}>
          <AppRoutes />
        </MemoryRouter>,
      );
      await user.click(screen.getByRole("button", { name: /demo alanına gir/i }));
      expect(
        await screen.findByRole("heading", { name: /demo kontrol paneli/i }),
      ).toBeInTheDocument();
    });
  });
});
