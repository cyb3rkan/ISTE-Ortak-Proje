/**
 * Auth flow tests — login, AuthProvider, ProtectedRoute, logout.
 *
 * `config.authMode` is forced to "jwt" via a module mock so the auth code
 * paths are exercised. The global `fetch` is stubbed per-test.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";

// Force jwt mode for every test in this file.
vi.mock("@/lib/config", async () => {
  const actual =
    await vi.importActual<typeof import("@/lib/config")>("@/lib/config");
  return {
    ...actual,
    config: { ...actual.config, authMode: "jwt" },
  };
});

import { AuthProvider } from "@/auth/AuthProvider";
import { ProtectedRoute } from "@/auth/ProtectedRoute";
import { LoginPage } from "@/pages/LoginPage";
import { getAccessToken } from "@/auth/tokenStore";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const LOGIN_OK = {
  access_token: "access-token-abc123",
  token_type: "bearer",
  expires_in: 900,
  user: { username: "admin", role: "admin" },
};

function Protected() {
  return <div>secret dashboard</div>;
}

function renderApp(initialPath = "/") {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Protected />
              </ProtectedRoute>
            }
          />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("auth flow", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    // Ensure each test starts with no token / no cookie.
    document.cookie = "";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("redirects an anonymous user from a protected route to /login", async () => {
    // Silent refresh on mount fails (no cookie) -> anonymous.
    fetchMock.mockResolvedValue(jsonResponse({ detail: "no cookie" }, 401));

    renderApp("/");

    await waitFor(() =>
      expect(screen.getByTestId("login-submit")).toBeInTheDocument(),
    );
    expect(screen.queryByText("secret dashboard")).not.toBeInTheDocument();
  });

  it("logs in with valid credentials and reaches the protected route", async () => {
    // 1) mount silent-refresh 401, 2) login 200.
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ detail: "no cookie" }, 401))
      .mockResolvedValueOnce(jsonResponse(LOGIN_OK, 200));

    renderApp("/");

    await waitFor(() =>
      expect(screen.getByTestId("login-submit")).toBeInTheDocument(),
    );

    await userEvent.type(screen.getByTestId("login-username"), "admin");
    await userEvent.type(screen.getByTestId("login-password"), "AdminPass123");
    await userEvent.click(screen.getByTestId("login-submit"));

    await waitFor(() =>
      expect(screen.getByText("secret dashboard")).toBeInTheDocument(),
    );
    // Token is held in memory.
    expect(getAccessToken()).toBe("access-token-abc123");
  });

  it("shows a generic error on invalid credentials", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ detail: "no cookie" }, 401))
      .mockResolvedValueOnce(
        jsonResponse({ detail: "Invalid username or password." }, 401),
      );

    renderApp("/login");

    await userEvent.type(screen.getByTestId("login-username"), "admin");
    await userEvent.type(screen.getByTestId("login-password"), "wrong");
    await userEvent.click(screen.getByTestId("login-submit"));

    // The backend's English detail is surfaced verbatim by LoginPage;
    // the alert MUST appear and reference an "invalid" credential signal
    // (English from the API, or Turkish if the API is localised later).
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        /invalid username or password|geçersiz kullanıcı adı veya (parola|şifre)/i,
      ),
    );
    expect(screen.queryByText("secret dashboard")).not.toBeInTheDocument();
  });

  it("never writes the access token to localStorage or sessionStorage", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ detail: "no cookie" }, 401))
      .mockResolvedValueOnce(jsonResponse(LOGIN_OK, 200));

    renderApp("/login");
    await userEvent.type(screen.getByTestId("login-username"), "admin");
    await userEvent.type(screen.getByTestId("login-password"), "AdminPass123");
    await userEvent.click(screen.getByTestId("login-submit"));

    await waitFor(() => expect(getAccessToken()).toBe("access-token-abc123"));

    // Walk every storage entry — the token must appear in neither.
    const dump = [
      ...Array.from({ length: localStorage.length }, (_, i) =>
        localStorage.getItem(localStorage.key(i) ?? ""),
      ),
      ...Array.from({ length: sessionStorage.length }, (_, i) =>
        sessionStorage.getItem(sessionStorage.key(i) ?? ""),
      ),
    ].join(" ");
    expect(dump).not.toContain("access-token-abc123");
  });

  it("hydrates the session from a valid refresh cookie on mount", async () => {
    // Silent refresh succeeds, then /auth/me returns the user.
    fetchMock
      .mockResolvedValueOnce(jsonResponse(LOGIN_OK, 200)) // /auth/refresh
      .mockResolvedValueOnce(
        jsonResponse({ username: "admin", role: "admin" }, 200),
      ); // /auth/me

    renderApp("/");

    await waitFor(() =>
      expect(screen.getByText("secret dashboard")).toBeInTheDocument(),
    );
  });
});
