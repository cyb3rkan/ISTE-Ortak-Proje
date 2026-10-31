/**
 * Giriş sayfası.
 *
 * Güvenlik notları:
 *  - Password alanı `autoComplete="current-password"` ve `type="password"`
 *    kullanır; değer yalnızca component state içinde tutulur ve hiçbir zaman loglanmaz.
 *  - Başarılı giriş sonrası access token, AuthProvider tarafından memory içinde tutulur;
 *    web storage içine hiçbir şey yazılmaz.
 *  - Hatalar genel şekilde gösterilir — backend zaten bilgi sızdırmayan
 *    "Geçersiz kullanıcı adı veya parola." mesajı döndürür.
 */

import { useState } from "react";
import type { FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";

import { useAuth } from "@/auth/useAuth";
import { AuthApiError } from "@/auth/authApi";
import { safeRedirectPath } from "@/auth/safeRedirect";

interface LocationState {
  from?: string;
}

export function LoginPage() {
  const { status, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  // Yalnızca uygulama içi path'lere dönülür (open-redirect koruması).
  const from = safeRedirectPath((location.state as LocationState | null)?.from);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Zaten giriş yapılmışsa doğrudan yönlendir.
  if (status === "authenticated") {
    return <Navigate to={from} replace />;
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    setError(null);
    setSubmitting(true);
    try {
      await login({ username, password });
      navigate(from, { replace: true });
    } catch (err) {
      if (err instanceof AuthApiError) {
        setError(err.message);
      } else {
        setError("Giriş başarısız oldu. Lütfen tekrar deneyin.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-[70vh] items-center justify-center">
      <section className="w-full max-w-sm rounded-lg border border-surface-border bg-surface-raised">
        <header className="border-b border-surface-border px-5 py-4">
          <div className="flex items-center gap-2">
            <span className="text-accent text-lg font-bold">◆</span>
            <h1 className="text-sm font-semibold text-slate-100">
              IOC Enricher — Giriş Yap
            </h1>
          </div>
        </header>
        <form className="space-y-4 p-5" onSubmit={handleSubmit} noValidate>
          <div>
            <label
              htmlFor="login-username"
              className="text-xs font-medium text-slate-400"
            >
              Kullanıcı Adı
            </label>
            <input
              id="login-username"
              name="username"
              type="text"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              data-testid="login-username"
              className="mt-1 w-full rounded-md border border-surface-border bg-surface px-3 py-2 text-sm text-slate-100 focus:border-accent focus:outline-hidden"
            />
          </div>
          <div>
            <label
              htmlFor="login-password"
              className="text-xs font-medium text-slate-400"
            >
              Parola
            </label>
            <input
              id="login-password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              data-testid="login-password"
              className="mt-1 w-full rounded-md border border-surface-border bg-surface px-3 py-2 text-sm text-slate-100 focus:border-accent focus:outline-hidden"
            />
          </div>

          {error ? (
            <p
              role="alert"
              className="rounded-md border border-risk-critical/40 bg-risk-critical/10 px-3 py-2 text-xs text-risk-critical"
            >
              {error}
            </p>
          ) : null}

          <button
            type="submit"
            disabled={submitting}
            data-testid="login-submit"
            className="w-full rounded-md bg-accent px-4 py-2 text-sm font-semibold text-slate-900 transition hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "Giriş yapılıyor…" : "Giriş Yap"}
          </button>
        </form>
      </section>
    </div>
  );
}