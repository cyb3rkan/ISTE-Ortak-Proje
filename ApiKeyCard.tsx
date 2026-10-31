/**
 * Tek bir sağlayıcı için kişisel API anahtarı kartı (demo).
 *
 * SECURITY:
 *  - Ham anahtar yalnızca bu bileşenin input state'inde, kaydedilene kadar
 *    yaşar; başarılı kayıttan sonra temizlenir. Input'un `name` özniteliği
 *    yoktur (form gönderimine/URL'ye düşmez) ve parola yöneticisi
 *    otomatik doldurması kapatılmaya çalışılır.
 *  - Mesajlar hiçbir zaman girilen değeri içermez; kayıtlı anahtar yalnızca
 *    maskeli son 4 karakterle gösterilir.
 */

import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router";

import { API_KEY_ERROR_STATUSES, validateApiKeyInput } from "../demoApiKeyService";
import type { ApiKeyMetadata, ApiKeyStatus, DemoApiKeyService } from "../demoApiKeyService";
import type { DemoProviderInfo } from "../demoProviders";
import { ConfirmDialog } from "./ConfirmDialog";
import { DEMO_ALERT } from "./DemoAuthCard";

type Tone = "ok" | "warn" | "error" | "neutral";

const STATUS_BADGES: Record<ApiKeyStatus, { label: string; tone: Tone }> = {
  not_configured: { label: "Anahtar eklenmemiş", tone: "neutral" },
  saved_unverified: { label: "Kayıtlı · doğrulanmadı", tone: "warn" },
  verification_skipped: { label: "Doğrulama yapılmadı", tone: "warn" },
  verified: { label: "Doğrulandı", tone: "ok" },
  invalid: { label: "Anahtar geçersiz", tone: "error" },
  permission_denied: { label: "Erişim/izin yok", tone: "error" },
  rate_limited: { label: "Kota/hız sınırı", tone: "warn" },
  provider_unreachable: { label: "Sağlayıcıya ulaşılamıyor", tone: "warn" },
  unexpected_error: { label: "Beklenmeyen hata", tone: "error" },
};

const TONE_CLASSES: Record<Tone, string> = {
  ok: "bg-risk-low/15 text-risk-low border-risk-low/40",
  warn: "bg-risk-medium/15 text-risk-medium border-risk-medium/40",
  error: "bg-risk-critical/15 text-risk-critical border-risk-critical/40",
  neutral: "bg-slate-500/15 text-slate-300 border-slate-500/40",
};

const STATUS_DETAILS: Partial<Record<ApiKeyStatus, string>> = {
  not_configured:
    "Henüz anahtar eklenmedi. Sağlayıcı hesabınızdan aldığınız anahtarı aşağıya ekleyebilirsiniz.",
  saved_unverified: "Anahtarın çalışıp çalışmadığı bilinmiyor; demo hiçbir sağlayıcıya bağlanmaz.",
  verification_skipped: "Son demo bağlantı denemesi gerçek bir doğrulama değildi.",
};

const ERROR_MESSAGES: Partial<Record<ApiKeyStatus, string>> = {
  invalid:
    "Sağlayıcı anahtarı kabul etmedi. Anahtarın eksiksiz ve doğru kopyalandığını kontrol edip yeniden girin.",
  permission_denied:
    "Hesabınızın bu sorgular için gerekli API erişimi veya izni yok gibi görünüyor. Sağlayıcı hesabınızdaki API erişimini kontrol edin.",
  rate_limited:
    "Kota veya hız sınırına ulaşıldı. Bir süre sonra tekrar deneyin ya da sağlayıcı hesabınızdaki kullanım limitlerini kontrol edin.",
  provider_unreachable:
    "Sağlayıcıya şu anda ulaşılamıyor. Sorun anahtarınızda olmayabilir; bir süre sonra tekrar deneyin.",
  unexpected_error:
    "Beklenmeyen bir hata oluştu. Tekrar deneyin; sorun sürerse anahtarı yeniden girin.",
};

const BUTTON =
  "min-h-10 rounded-md border border-surface-border bg-surface px-3 py-2 text-xs font-medium text-slate-200 hover:border-accent/50 focus-visible:outline-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-60";

interface ApiKeyCardProps {
  provider: DemoProviderInfo;
  metadata: ApiKeyMetadata;
  service: DemoApiKeyService;
  onChange: (metadata: ApiKeyMetadata) => void;
  /** Rehberden dönüldüğünde anahtar alanına odaklan. */
  focusInputOnMount?: boolean;
}

type Busy = "save" | "check" | "delete" | null;

export function ApiKeyCard({
  provider,
  metadata,
  service,
  onChange,
  focusInputOnMount = false,
}: ApiKeyCardProps) {
  const baseId = useId();
  const titleId = `${baseId}-title`;
  const inputId = `${baseId}-key`;
  const hintId = `${baseId}-hint`;
  const errorId = `${baseId}-error`;
  const guidePath = `/demo/api-keys/guides/${provider.id}`;

  const [value, setValue] = useState("");
  const [visible, setVisible] = useState(false);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<Busy>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [focusInput, setFocusInput] = useState(focusInputOnMount);
  const inputRef = useRef<HTMLInputElement>(null);

  // Odak isteği, onay penceresinin odak iadesinden sonra uygulanır.
  useEffect(() => {
    if (!focusInput) return;
    inputRef.current?.focus();
    setFocusInput(false);
  }, [focusInput]);

  const configured = metadata.status !== "not_configured";
  const isError = API_KEY_ERROR_STATUSES.includes(metadata.status);
  const badge = STATUS_BADGES[metadata.status];

  async function handleSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setNotice("");
    setActionError(null);

    const error = validateApiKeyInput(value);
    setFieldError(error);
    if (error) {
      inputRef.current?.focus();
      return;
    }

    setBusy("save");
    try {
      const result = await service.saveKey(provider.id, value);
      if (result.ok) {
        setValue("");
        setVisible(false);
        onChange(result.key);
        setNotice("Demo anahtarı kaydedildi. Anahtar doğrulanmadı ve sağlayıcıya gönderilmedi.");
      } else {
        setActionError(
          result.error === "invalid_input"
            ? "Anahtar kaydedilemedi. Girdiğiniz değeri kontrol edip tekrar deneyin."
            : "Anahtar kaydedilemedi (demo senaryosu). Lütfen tekrar deneyin.",
        );
      }
    } catch {
      setActionError("Anahtar kaydedilemedi. Lütfen tekrar deneyin.");
    }
    setBusy(null);
  }

  async function handleCheck() {
    if (busy) return;
    setNotice("");
    setActionError(null);
    setBusy("check");
    try {
      const result = await service.checkKey(provider.id);
      if (result.ok) {
        onChange(result.key);
        if (result.key.status === "verification_skipped") {
          setNotice("Demo: sağlayıcıya bağlanılmadı, anahtar doğrulanmadı.");
        }
      } else {
        setActionError("Önce bir anahtar kaydedin.");
      }
    } catch {
      setActionError("Bağlantı denemesi tamamlanamadı. Lütfen tekrar deneyin.");
    }
    setBusy(null);
  }

  async function handleDelete() {
    setBusy("delete");
    try {
      const result = await service.deleteKey(provider.id);
      onChange(result.key);
      setNotice("Demo anahtarı silindi.");
      setFocusInput(true);
    } catch {
      setActionError("Anahtar silinemedi. Lütfen tekrar deneyin.");
    }
    setBusy(null);
    setConfirmOpen(false);
  }

  return (
    <article
      aria-labelledby={titleId}
      className="flex flex-col rounded-lg border border-surface-border bg-surface-raised"
    >
      <header className="flex flex-wrap items-start justify-between gap-2 border-b border-surface-border px-4 py-3">
        <div className="min-w-0">
          <h2 id={titleId} className="text-sm font-semibold text-slate-100">
            {provider.name}
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">{provider.description}</p>
          <p className="mt-0.5 text-[11px] text-slate-500">IOC türleri: {provider.iocTypes}</p>
        </div>
        <span
          className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs font-medium ${TONE_CLASSES[badge.tone]}`}
        >
          <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
          {badge.label}
        </span>
      </header>

      <div className="flex flex-1 flex-col gap-3 p-4">
        {configured ? (
          <p className="text-xs text-slate-400">
            Kayıtlı anahtar:{" "}
            <span className="font-mono text-slate-200">
              {metadata.last4 ? `•••• ${metadata.last4}` : "••••"}
            </span>
            {metadata.last4 ? null : " (kısa anahtar; karakter gösterilmez)"}
            {metadata.updatedAt ? (
              <>
                {" · "}Güncellendi:{" "}
                <time dateTime={metadata.updatedAt.toISOString()}>
                  {metadata.updatedAt.toLocaleTimeString("tr-TR")}
                </time>
              </>
            ) : null}
          </p>
        ) : null}

        {STATUS_DETAILS[metadata.status] ? (
          <p className="text-xs text-slate-400">{STATUS_DETAILS[metadata.status]}</p>
        ) : null}

        {isError ? (
          <div role="alert" className={`space-y-2 ${DEMO_ALERT}`}>
            <p>{ERROR_MESSAGES[metadata.status]}</p>
            <p className="text-slate-300">
              Bu sorun yalnızca {provider.name} için geçerli; diğer sağlayıcılar bundan
              otomatik olarak etkilenmez ve sonuçları kullanılabilir kalır.
            </p>
            {metadata.simulated ? (
              <p className="text-slate-400">
                Demo senaryosu: bu sonuç geliştirici demo panelinden seçildi; sağlayıcıya
                bağlanılmadı.
              </p>
            ) : null}
            <div className="flex flex-wrap gap-x-4 gap-y-1 pt-1">
              <button
                type="button"
                onClick={() => inputRef.current?.focus()}
                className="font-medium text-accent underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent"
              >
                Anahtarı düzenle
              </button>
              <Link
                to={guidePath}
                className="font-medium text-accent underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent"
              >
                API anahtarı nasıl alınır?
              </Link>
            </div>
          </div>
        ) : null}

        <form onSubmit={handleSave} noValidate className="space-y-2">
          <label htmlFor={inputId} className="text-xs font-medium text-slate-400">
            {provider.name} API anahtarı
          </label>
          <div className="flex gap-2">
            <input
              id={inputId}
              ref={inputRef}
              type={visible ? "text" : "password"}
              value={value}
              onChange={(e) => {
                setValue(e.target.value);
                if (fieldError) setFieldError(validateApiKeyInput(e.target.value));
              }}
              autoComplete="off"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              data-lpignore="true"
              data-1p-ignore=""
              data-form-type="other"
              placeholder={configured ? "Yeni anahtarı yapıştırın" : "Anahtarı yapıştırın"}
              aria-invalid={fieldError ? true : undefined}
              aria-describedby={[fieldError ? errorId : null, hintId].filter(Boolean).join(" ")}
              className={`min-w-0 flex-1 rounded-md border bg-surface px-3 py-2 font-mono text-sm text-slate-100 focus:outline-hidden focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-accent ${
                fieldError ? "border-risk-critical/70" : "border-surface-border focus:border-accent"
              }`}
            />
            <button
              type="button"
              onClick={() => setVisible((v) => !v)}
              aria-controls={inputId}
              className={`${BUTTON} shrink-0`}
            >
              {visible ? "Anahtarı gizle" : "Anahtarı göster"}
            </button>
          </div>
          {fieldError ? (
            <p id={errorId} className="text-xs text-risk-critical">
              {fieldError}
            </p>
          ) : null}
          <p id={hintId} className="text-[11px] text-slate-500">
            Demo: anahtar yalnızca bu oturumda geçici olarak işlenir, sağlayıcıya gönderilmez
            ve kaydedildikten sonra tamamı gösterilmez.
          </p>
          <button
            type="submit"
            disabled={busy !== null}
            className="min-h-10 w-full rounded-md bg-accent px-4 py-2 text-sm font-semibold text-slate-900 transition hover:bg-accent/90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto"
          >
            {busy === "save" ? "Kaydediliyor…" : configured ? "Anahtarı değiştir" : "Anahtarı kaydet"}
          </button>
        </form>

        {actionError ? (
          <p role="alert" className={DEMO_ALERT}>
            {actionError}
          </p>
        ) : null}
        <p role="status" className="text-xs text-slate-300">
          {notice}
        </p>

        <div className="mt-auto flex flex-wrap items-center gap-2 border-t border-surface-border pt-3">
          {configured ? (
            <>
              <button
                type="button"
                onClick={handleCheck}
                disabled={busy !== null}
                className={BUTTON}
              >
                {busy === "check" ? "Deneniyor…" : "Bağlantıyı dene (demo)"}
              </button>
              <button
                type="button"
                onClick={() => setConfirmOpen(true)}
                disabled={busy !== null}
                className={`${BUTTON} text-risk-critical`}
              >
                Anahtarı sil
              </button>
            </>
          ) : null}
          <Link
            to={guidePath}
            className="ml-auto text-xs font-medium text-accent underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent"
          >
            API anahtarı nasıl alınır?
          </Link>
        </div>
      </div>

      <ConfirmDialog
        open={confirmOpen}
        title={`${provider.name} anahtarı silinsin mi?`}
        confirmLabel="Anahtarı sil"
        busy={busy === "delete"}
        onConfirm={handleDelete}
        onCancel={() => setConfirmOpen(false)}
      >
        Bu demo oturumundaki {provider.name} anahtar kaydı silinecek. Daha sonra yeni bir
        anahtar ekleyebilirsiniz.
      </ConfirmDialog>
    </article>
  );
}
