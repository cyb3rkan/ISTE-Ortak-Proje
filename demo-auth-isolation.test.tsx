/**
 * Demo alanının gerçek auth katmanından yalıtımı — `VITE_AUTH_MODE=jwt`.
 *
 *  - `/demo/*` gerçek AuthProvider'ı mount etmez: `/auth/refresh`, health
 *    veya başka bir backend isteği oluşmaz.
 *  - Gerçek uygulama rotaları AuthProvider'ın sessiz yenilemesini ve
 *    ProtectedRoute korumasını aynen sürdürür.
 *  - Demo giriş/çıkışı gerçek token store'u değiştirmez.
 *  - Bayrak kapalıyken `/demo/*` mevcut 404 davranışını korur.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RouterProvider, createMemoryRouter } from "react-router";

const flags = vi.hoisted(() => ({ prototypeMode: true }));

vi.mock("@/lib/config", async () => {
  const actual =
    await vi.importActual<typeof import("@/lib/config")>("@/lib/config");
  return {
    ...actual,
    config: {
      ...actual.config,
      authMode: "jwt",
      get prototypeMode() {
        return flags.prototypeMode;
      },
    },
  };
});

import { App } from "@/App";
import { clearAccessToken, getAccessToken, setAccessToken } from "@/auth/tokenStore";

const DEMO_PATHS = [
  "/demo",
  "/demo/login",
  "/demo/signup",
  "/demo/verify-email",
  "/demo/forgot-password",
  "/demo/reset-password",
  "/demo/dashboard",
  "/demo/api-keys",
  "/demo/api-keys/guides/shodan",
  "/demo/admin/users",
];

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function renderApp(path: string) {
  const router = createMemoryRouter([{ path: "*", element: <App /> }], {
    initialEntries: [path],
  });
  render(<RouterProvider router={router} />);
  return router;
}

function requestedUrls(fetchMock: ReturnType<typeof vi.fn>): string[] {
  return fetchMock.mock.calls.map((call) => String(call[0]));
}

/** Bekleyen mikro görevlerin (ör. mount sırasındaki sessiz yenileme) çalışmasını bekler. */
async function flush() {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 20));
  });
}

describe("demo alanı — gerçek auth yalıtımı (VITE_AUTH_MODE=jwt)", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    flags.prototypeMode = true;
    fetchMock.mockReset();
    // Gerçek backend yok: her istek 401 döner (oturum yok).
    fetchMock.mockImplementation(async () => jsonResponse({ detail: "unauthorized" }, 401));
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    clearAccessToken();
  });

  it.each(DEMO_PATHS)("%s gerçek auth yenilemesi veya backend isteği yapmaz", async (path) => {
    renderApp(path);
    await flush();
    expect(screen.getByRole("region", { name: /demo prototipi/i })).toBeInTheDocument();
    expect(requestedUrls(fetchMock)).toEqual([]);
  });

  it("demo akışı boyunca (giriş, sayfalar arası geçiş, çıkış) hiçbir istek oluşmaz ve token store değişmez", async () => {
    const user = userEvent.setup();
    setAccessToken("real-session-token");
    renderApp("/demo/login");

    await user.click(screen.getByRole("radio", { name: /^yönetici/i }));
    await user.click(screen.getByRole("button", { name: /demo alanına gir/i }));
    await screen.findByRole("heading", { name: /demo kontrol paneli/i });
    await user.click(screen.getByRole("link", { name: "API Anahtarlarım" }));
    await screen.findByRole("article", { name: "Shodan" });
    await user.click(screen.getByRole("link", { name: "Kullanıcı yönetimi" }));
    await screen.findByRole("list", { name: "Demo kullanıcıları" });
    await user.click(screen.getByRole("button", { name: /demo oturumunu kapat/i }));
    await screen.findByRole("heading", { name: /demo girişi/i });
    await flush();

    expect(requestedUrls(fetchMock)).toEqual([]);
    expect(getAccessToken()).toBe("real-session-token");
  });

  it("gerçek korumalı rota sessiz yenileme dener ve oturum yoksa /login'e yönlendirir", async () => {
    renderApp("/analyze");
    expect(await screen.findByTestId("login-username")).toBeInTheDocument();
    expect(requestedUrls(fetchMock).some((u) => u.endsWith("/api/v1/auth/refresh"))).toBe(true);
    expect(screen.queryByRole("region", { name: /demo prototipi/i })).not.toBeInTheDocument();
  });

  it("gerçek oturum yenilenebiliyorsa korumalı rota açılır ve Topbar kullanıcıyı gösterir", async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/refresh")) {
        return jsonResponse({
          access_token: "refreshed-token",
          token_type: "bearer",
          expires_in: 900,
          user: { username: "analist", role: "analyst" },
        });
      }
      if (url.endsWith("/auth/me")) return jsonResponse({ username: "analist", role: "analyst" });
      return jsonResponse({ detail: "not mocked" }, 503);
    });

    renderApp("/cache");
    const header = await screen.findByRole("banner");
    await waitFor(() => expect(within(header).getByText("analist")).toBeInTheDocument());
    expect(getAccessToken()).toBe("refreshed-token");
    expect(within(header).getByRole("button", { name: /çıkış yap/i })).toBeInTheDocument();
  });

  it("demo'dan gerçek uygulamaya dönünce gerçek AuthProvider yeniden çalışır", async () => {
    const router = renderApp("/demo/login");
    await flush();
    expect(requestedUrls(fetchMock)).toEqual([]);

    await act(() => router.navigate("/"));
    expect(await screen.findByTestId("login-username")).toBeInTheDocument();
    expect(requestedUrls(fetchMock).some((u) => u.endsWith("/api/v1/auth/refresh"))).toBe(true);
  });

  it("bayrak kapalıyken /demo/* mevcut 404 davranışını (gerçek kabukta) korur", async () => {
    flags.prototypeMode = false;
    renderApp("/demo/api-keys");
    expect(await screen.findByText("404")).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: /demo prototipi/i })).not.toBeInTheDocument();
  });
});
