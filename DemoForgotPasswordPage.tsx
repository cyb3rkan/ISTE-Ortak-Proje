/**
 * Demo "Parolamı unuttum" ekranı.
 *
 * E-posta gönderilmez ve hesabın varlığı doğrulanmaz. Başarı mesajı, gerçek
 * sistemde hesap numaralandırmayı önlemek için adresin kayıtlı olup
 * olmadığını açıklamayan nötr bir dil kullanır.
 */

import { useRef, useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router";

import {
  DEMO_ALERT,
  DEMO_LINK,
  DEMO_PRIMARY_BUTTON,
  DEMO_SUCCESS,
  DemoAuthCard,
} from "../components/DemoAuthCard";
import { DemoDevPanel } from "../components/DemoDevPanel";
import { DemoTextField } from "../components/DemoTextField";
import { EMAIL_MAX_LENGTH, validateEmail } from "../demoValidation";
import { useDemoAccountFlow } from "../useDemoAccountFlow";

export function DemoForgotPasswordPage() {
  const { service } = useDemoAccountFlow();

  const [email, setEmail] = useState("");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [accepted, setAccepted] = useState(false);
  const emailRef = useRef<HTMLInputElement>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    setRequestError(null);

    const error = validateEmail(email);
    setFieldError(error);
    if (error) {
      emailRef.current?.focus();
      return;
    }

    setSubmitting(true);
    try {
      const result = await service.requestPasswordReset({ email: email.trim() });
      if (result.status === "accepted") {
        setAccepted(true);
      } else {
        setRequestError(
          "Sıfırlama talebi şu anda işlenemedi (demo servis hatası). Lütfen daha sonra tekrar deneyin.",
        );
      }
    } catch {
      setRequestError("Sıfırlama talebi gönderilemedi. Lütfen tekrar deneyin.");
    }
    setSubmitting(false);
  }

  function handleRetry() {
    setAccepted(false);
    setEmail("");
    setFieldError(null);
  }

  return (
    <div className="space-y-4">
      <DemoAuthCard
        title="IOC Enricher — Parolamı Unuttum"
        description={
          <p>
            Parola yenileme akışı bir prototiptir: e-posta gönderilmez ve hesap
            erişimi doğrulanmaz.
          </p>
        }
        footer={
          <Link to="/demo/login" className={DEMO_LINK}>
            Demo girişine dön
          </Link>
        }
      >
        {accepted ? (
          <div className="space-y-4">
            <div role="status" aria-label="Sıfırlama talebi durumu" className={DEMO_SUCCESS}>
              <p className="font-medium text-risk-low">Demo talebi alındı.</p>
              <p className="mt-1">
                Demo: gerçek e-posta gönderilmedi. Gerçek sistemde, bu adres
                kayıtlıysa parola sıfırlama bağlantısı gönderilir; güvenlik
                nedeniyle adresin kayıtlı olup olmadığı belirtilmez.
              </p>
            </div>
            <Link
              to="/demo/reset-password"
              className={`block text-center ${DEMO_PRIMARY_BUTTON}`}
            >
              Demo sıfırlama ekranını aç
            </Link>
            <button
              type="button"
              onClick={handleRetry}
              className={`block w-full text-center text-xs ${DEMO_LINK}`}
            >
              Farklı bir adres gir
            </button>
          </div>
        ) : (
          <form className="space-y-4" onSubmit={handleSubmit} noValidate>
            <DemoTextField
              id="forgot-email"
              label="E-posta"
              type="email"
              autoComplete="email"
              maxLength={EMAIL_MAX_LENGTH}
              value={email}
              onChange={(v) => {
                setEmail(v);
                if (fieldError) setFieldError(validateEmail(v));
              }}
              error={fieldError}
              inputRef={emailRef}
            />

            {requestError ? (
              <p role="alert" className={DEMO_ALERT}>
                {requestError}
              </p>
            ) : null}

            <button type="submit" disabled={submitting} className={DEMO_PRIMARY_BUTTON}>
              {submitting ? "Talep işleniyor…" : "Sıfırlama bağlantısı iste"}
            </button>
          </form>
        )}
      </DemoAuthCard>

      <DemoDevPanel fields={["passwordResetRequest"]} />
    </div>
  );
}
