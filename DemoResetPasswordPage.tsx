/**
 * Demo yeni parola belirleme ekranı.
 *
 * Gerçek sistemde bu ekran e-postadaki tek kullanımlık bağlantıyla açılır;
 * demoda bağlantı/token yoktur. Yeni parola yalnızca bu bileşenin state'inde
 * doğrulama için tutulur; saklanmaz, loglanmaz ve gönderilmez.
 */

import { useRef, useState } from "react";
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
import { PasswordRequirementList } from "../components/PasswordRequirementList";
import {
  PASSWORD_MAX_LENGTH,
  validatePassword,
  validatePasswordConfirmation,
} from "../demoValidation";
import { useDemoAccountFlow } from "../useDemoAccountFlow";

interface ResetErrors {
  password: string | null;
  confirmation: string | null;
}

export function DemoResetPasswordPage() {
  const { service } = useDemoAccountFlow();
  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [errors, setErrors] = useState<ResetErrors | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [resultError, setResultError] = useState<"link_expired" | "failed" | null>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmationRef = useRef<HTMLInputElement>(null);

  function validate(nextPassword: string, nextConfirmation: string): ResetErrors {
    return {
      password: validatePassword(nextPassword),
      confirmation: validatePasswordConfirmation(nextPassword, nextConfirmation),
    };
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    setResultError(null);

    const nextErrors = validate(password, confirmation);
    setErrors(nextErrors);
    if (nextErrors.password) {
      passwordRef.current?.focus();
      return;
    }
    if (nextErrors.confirmation) {
      confirmationRef.current?.focus();
      return;
    }

    setSubmitting(true);
    try {
      const result = await service.resetPassword({ newPassword: password });
      if (result.status === "password_updated") {
        navigate("/demo/login", { replace: true, state: { demoNotice: "password-reset" } });
        return;
      }
      setResultError("link_expired");
    } catch {
      setResultError("failed");
    }
    setSubmitting(false);
  }

  return (
    <div className="space-y-4">
      <DemoAuthCard
        title="IOC Enricher — Yeni Parola Belirle"
        description={
          <p>
            Gerçek sistemde bu ekran e-postadaki tek kullanımlık bağlantıyla
            açılır. Demoda bağlantı doğrulanmaz; yeni parola saklanmaz ve
            hiçbir yere gönderilmez.
          </p>
        }
        footer={
          <Link to="/demo/login" className={DEMO_LINK}>
            Demo girişine dön
          </Link>
        }
      >
        <form className="space-y-4" onSubmit={handleSubmit} noValidate>
          <div>
            <DemoTextField
              id="reset-password"
              label="Yeni parola"
              type="password"
              autoComplete="new-password"
              maxLength={PASSWORD_MAX_LENGTH}
              value={password}
              onChange={(v) => {
                setPassword(v);
                if (errors) setErrors(validate(v, confirmation));
              }}
              error={errors?.password}
              describedBy="reset-password-requirements"
              inputRef={passwordRef}
            />
            <PasswordRequirementList id="reset-password-requirements" password={password} />
          </div>
          <DemoTextField
            id="reset-password-confirmation"
            label="Yeni parola tekrarı"
            type="password"
            autoComplete="new-password"
            maxLength={PASSWORD_MAX_LENGTH}
            value={confirmation}
            onChange={(v) => {
              setConfirmation(v);
              if (errors) setErrors(validate(password, v));
            }}
            error={errors?.confirmation}
            inputRef={confirmationRef}
          />

          {resultError === "link_expired" ? (
            <div role="alert" className={DEMO_ALERT}>
              Sıfırlama bağlantısının süresi dolmuş (demo senaryosu).{" "}
              <Link to="/demo/forgot-password" className="underline">
                Yeni bağlantı isteyin
              </Link>
              .
            </div>
          ) : null}
          {resultError === "failed" ? (
            <p role="alert" className={DEMO_ALERT}>
              Parola güncellenemedi. Lütfen tekrar deneyin.
            </p>
          ) : null}

          <button type="submit" disabled={submitting} className={DEMO_PRIMARY_BUTTON}>
            {submitting ? "Parola güncelleniyor…" : "Parolayı güncelle"}
          </button>
        </form>
      </DemoAuthCard>

      <DemoDevPanel fields={["passwordReset"]} />
    </div>
  );
}
