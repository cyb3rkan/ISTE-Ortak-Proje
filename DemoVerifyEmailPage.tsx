/**
 * Demo e-posta kodu doğrulama ekranı.
 *
 * Hiçbir e-posta gönderilmez. Girilen kod yalnızca bu bileşenin state'inde
 * tutulur; hata mesajlarında gösterilmez, saklanmaz ve loglanmaz.
 */

import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "react-router";

import {
  DEMO_ALERT,
  DEMO_LINK,
  DEMO_PRIMARY_BUTTON,
  DemoAuthCard,
} from "../components/DemoAuthCard";
import { DemoDevPanel } from "../components/DemoDevPanel";
import { DemoTextField } from "../components/DemoTextField";
import { maskEmail, validateVerificationCode } from "../demoValidation";
import { useCountdown } from "../useCountdown";
import { useDemoAccountFlow } from "../useDemoAccountFlow";

const VERIFY_ERRORS = {
  invalid_code: "Kod hatalı. Kodu kontrol edip tekrar deneyin.",
  expired_code: "Kodun süresi dolmuş. Yeni bir kod isteyip tekrar deneyin.",
} as const;

export function DemoVerifyEmailPage() {
  const { service, pendingEmail, setPendingEmail } = useDemoAccountFlow();
  const navigate = useNavigate();

  const [code, setCode] = useState("");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  const [resendUntil, setResendUntil] = useState<number | null>(null);
  const [resending, setResending] = useState(false);
  const [resendNotice, setResendNotice] = useState<string | null>(null);
  const [resendError, setResendError] = useState<string | null>(null);
  const secondsLeft = useCountdown(resendUntil);

  if (!pendingEmail) {
    return (
      <DemoAuthCard
        title="IOC Enricher — E-posta Doğrulama"
        description={<p>Bu ekran demo kayıt akışının bir parçasıdır.</p>}
      >
        <div className="space-y-3 text-center text-sm text-slate-300">
          <p>Doğrulanacak bir demo kaydı yok.</p>
          <p className="text-xs text-slate-400">
            Önce demo hesap oluşturma formunu doldurun.
          </p>
          <Link to="/demo/signup" className={`inline-block text-sm ${DEMO_LINK}`}>
            Demo hesap oluşturma ekranına git
          </Link>
        </div>
      </DemoAuthCard>
    );
  }

  async function handleVerify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (verifying || !pendingEmail) return;
    setVerifyError(null);

    const error = validateVerificationCode(code);
    setFieldError(error);
    if (error) return;

    setVerifying(true);
    try {
      const result = await service.verifyEmail({ email: pendingEmail, code });
      if (result.status === "verified") {
        setPendingEmail(null);
        navigate("/demo/login", { replace: true, state: { demoNotice: "email-verified" } });
        return;
      }
      setVerifyError(VERIFY_ERRORS[result.status]);
    } catch {
      setVerifyError("Doğrulama şu anda tamamlanamadı. Lütfen tekrar deneyin.");
    }
    setVerifying(false);
  }

  async function handleResend() {
    if (resending || secondsLeft > 0 || !pendingEmail) return;
    setResendError(null);
    setResendNotice(null);
    setResending(true);
    try {
      const result = await service.resendVerificationCode(pendingEmail);
      if (result.status === "sent") {
        setResendUntil(Date.now() + result.cooldownSeconds * 1000);
        setResendNotice(
          "Demo: gerçek e-posta gönderilmedi. Yeni kod gönderilmiş gibi davranılıyor; demo kodu değişmedi.",
        );
      } else {
        setResendUntil(Date.now() + result.retryAfterSeconds * 1000);
        setResendError(
          `Çok sık kod istendi. ${result.retryAfterSeconds} sn sonra tekrar deneyin.`,
        );
      }
    } catch {
      setResendError("Kod tekrar gönderilemedi. Lütfen daha sonra tekrar deneyin.");
    }
    setResending(false);
  }

  let resendLabel = "Kodu tekrar gönder";
  if (resending) resendLabel = "Gönderiliyor…";
  else if (secondsLeft > 0) resendLabel = `Tekrar gönder (${secondsLeft} sn)`;

  return (
    <div className="space-y-4">
      <DemoAuthCard
        title="IOC Enricher — E-posta Doğrulama"
        description={
          <p>
            Demo: gerçek e-posta gönderilmedi. Gerçek sistemde 6 haneli kod{" "}
            <strong className="font-medium text-slate-200">{maskEmail(pendingEmail)}</strong>{" "}
            adresine gönderilecek.
          </p>
        }
        footer={
          <Link to="/demo/signup" className={DEMO_LINK}>
            Farklı bir e-posta ile kayıt ol
          </Link>
        }
      >
        <form className="space-y-4" onSubmit={handleVerify} noValidate>
          <DemoTextField
            id="verify-code"
            label="Doğrulama kodu"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            value={code}
            onChange={(v) => setCode(v.replace(/\D/g, "").slice(0, 6))}
            error={fieldError}
          />

          {verifyError ? (
            <p role="alert" className={DEMO_ALERT}>
              {verifyError}
            </p>
          ) : null}

          <button type="submit" disabled={verifying} className={DEMO_PRIMARY_BUTTON}>
            {verifying ? "Kod doğrulanıyor…" : "Kodu doğrula"}
          </button>
        </form>

        <div className="mt-4 space-y-2 border-t border-surface-border pt-4">
          <button
            type="button"
            onClick={handleResend}
            disabled={resending || secondsLeft > 0}
            className="w-full rounded-md border border-surface-border bg-surface px-4 py-2 text-sm font-medium text-slate-200 hover:border-accent/50 focus-visible:outline-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-60"
          >
            {resendLabel}
          </button>
          <p role="status" aria-label="Tekrar gönderme durumu" className="text-xs text-slate-400">
            {resendNotice}
          </p>
          {resendError ? (
            <p role="alert" className={DEMO_ALERT}>
              {resendError}
            </p>
          ) : null}
        </div>
      </DemoAuthCard>

      <DemoDevPanel fields={["verifyCode", "resendCode"]} showDemoCode />
    </div>
  );
}
