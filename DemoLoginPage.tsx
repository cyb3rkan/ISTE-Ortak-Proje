/**
 * Demo giriş ekranı.
 *
 * Gerçek `/login` sayfasından ayrıdır: kimlik bilgisi istemez, kimlik
 * doğrulamaz ve hesap oluşturmaz. Kullanıcı yalnızca demo arayüzünü hangi
 * rolle göreceğini seçer. Demo hesap/parola akışlarından dönüldüğünde,
 * yönlendirme state'indeki bildirim anahtarına göre demo bilgi notu gösterir
 * (state yalnızca sabit bir anahtar taşır; parola, kod veya e-posta taşımaz).
 */

import { useState } from "react";
import type { FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router";

import { DEMO_ROLE_LABELS } from "../demoTypes";
import { useDemoSession } from "../useDemoSession";

const ROLE_DESCRIPTIONS = {
  analyst: "Sıradan kullanıcı görünümü (analyst rolü).",
  admin: "Tek yönetici görünümü (admin rolü).",
} as const;

const DEMO_NOTICES = {
  "email-verified":
    "Demo e-posta doğrulaması tamamlandı. Gerçek bir hesap oluşturulmadı; devam etmek için bir demo rolü seçin.",
  "password-reset":
    "Demo parola yenileme tamamlandı. Hiçbir parola değiştirilmedi veya saklanmadı; devam etmek için bir demo rolü seçin.",
} as const;

type DemoNoticeKey = keyof typeof DEMO_NOTICES;

function readDemoNotice(state: unknown): DemoNoticeKey | null {
  if (typeof state !== "object" || state === null || !("demoNotice" in state)) {
    return null;
  }
  const key = (state as { demoNotice: unknown }).demoNotice;
  return typeof key === "string" && key in DEMO_NOTICES ? (key as DemoNoticeKey) : null;
}

export function DemoLoginPage() {
  const { session, accounts, startSession } = useDemoSession();
  const navigate = useNavigate();
  const notice = readDemoNotice(useLocation().state);

  // En az yetkili rol varsayılan olarak seçilir.
  const [selectedId, setSelectedId] = useState(
    () => accounts.find((a) => a.role === "analyst")?.id ?? accounts[0]?.id ?? "",
  );
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (session) {
    return <Navigate to="/demo/dashboard" replace />;
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    setError(null);
    setSubmitting(true);
    try {
      await startSession(selectedId);
      navigate("/demo/dashboard", { replace: true });
    } catch {
      setError("Demo oturumu başlatılamadı. Lütfen bir rol seçip tekrar deneyin.");
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <section className="w-full max-w-md rounded-lg border border-surface-border bg-surface-raised">
        <header className="border-b border-surface-border px-5 py-4">
          <div className="flex items-center gap-2">
            <span className="text-accent text-lg font-bold" aria-hidden>
              ◆
            </span>
            <h1 className="text-sm font-semibold text-slate-100">
              IOC Enricher — Demo Girişi
            </h1>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Bu ekran gerçek bir hesap oluşturmaz ve kimlik doğrulaması yapmaz.
            E-posta, parola veya API anahtarı istenmez; yalnızca demo arayüzünü
            hangi rolle göreceğinizi seçersiniz.
          </p>
        </header>
        <form className="space-y-4 p-5" onSubmit={handleSubmit} noValidate>
          {notice ? (
            <p
              role="status"
              aria-label="Demo bildirimi"
              className="rounded-md border border-risk-low/40 bg-risk-low/10 px-3 py-2 text-xs text-slate-200"
            >
              {DEMO_NOTICES[notice]}
            </p>
          ) : null}
          <fieldset className="space-y-2">
            <legend className="text-xs font-medium text-slate-400">
              Demo rolü
            </legend>
            {accounts.map((account) => {
              const inputId = `demo-account-${account.id}`;
              const descriptionId = `${inputId}-description`;
              return (
                <label
                  key={account.id}
                  htmlFor={inputId}
                  className={`flex cursor-pointer items-start gap-3 rounded-md border px-3 py-2.5 transition-colors has-focus-visible:outline-2 has-focus-visible:outline-accent ${
                    selectedId === account.id
                      ? "border-accent/60 bg-accent/10"
                      : "border-surface-border bg-surface hover:border-accent/40"
                  }`}
                >
                  <input
                    id={inputId}
                    type="radio"
                    name="demo-account"
                    value={account.id}
                    checked={selectedId === account.id}
                    onChange={() => setSelectedId(account.id)}
                    aria-describedby={descriptionId}
                    className="mt-0.5 accent-accent"
                  />
                  <span className="min-w-0">
                    <span className="block text-sm font-medium text-slate-100">
                      {DEMO_ROLE_LABELS[account.role]}
                    </span>
                    <span id={descriptionId} className="block text-xs text-slate-400">
                      {account.displayName} · {ROLE_DESCRIPTIONS[account.role]}
                    </span>
                  </span>
                </label>
              );
            })}
          </fieldset>

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
            disabled={submitting || !selectedId}
            className="w-full rounded-md bg-accent px-4 py-2 text-sm font-semibold text-slate-900 transition hover:bg-accent/90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "Demo alanı açılıyor…" : "Demo alanına gir"}
          </button>

          <nav
            aria-label="Demo hesap akışları"
            className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1 border-t border-surface-border pt-4 text-xs"
          >
            <Link
              to="/demo/signup"
              className="text-accent hover:underline focus-visible:outline-2 focus-visible:outline-accent"
            >
              Hesap oluştur
            </Link>
            <Link
              to="/demo/forgot-password"
              className="text-accent hover:underline focus-visible:outline-2 focus-visible:outline-accent"
            >
              Parolamı unuttum
            </Link>
          </nav>

          <p className="text-center text-xs text-slate-400">
            Gerçek hesabınızla çalışmak için{" "}
            <Link to="/" className="text-accent hover:underline">
              gerçek uygulamaya dönün
            </Link>
            .
          </p>
        </form>
      </section>
    </div>
  );
}
