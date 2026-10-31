/**
 * Demo hesap oluşturma ekranı.
 *
 * Gerçek hesap oluşturmaz. Parola yalnızca bu bileşenin state'inde,
 * form doğrulaması için tutulur; saklanmaz, loglanmaz ve sayfadan
 * çıkıldığında atılır.
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
import { DemoTextField } from "../components/DemoTextField";
import { PasswordRequirementList } from "../components/PasswordRequirementList";
import {
  DISPLAY_NAME_MAX_LENGTH,
  EMAIL_MAX_LENGTH,
  PASSWORD_MAX_LENGTH,
  validateDisplayName,
  validateEmail,
  validatePassword,
  validatePasswordConfirmation,
} from "../demoValidation";
import { useDemoAccountFlow } from "../useDemoAccountFlow";

type Field = "displayName" | "email" | "password" | "confirmation";
type FieldErrors = Record<Field, string | null>;

const FIELD_ORDER: Field[] = ["displayName", "email", "password", "confirmation"];

export function DemoSignupPage() {
  const { service, setPendingEmail } = useDemoAccountFlow();
  const navigate = useNavigate();

  const [values, setValues] = useState<Record<Field, string>>({
    displayName: "",
    email: "",
    password: "",
    confirmation: "",
  });
  const [errors, setErrors] = useState<FieldErrors | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const refs: Record<Field, React.RefObject<HTMLInputElement>> = {
    displayName: useRef<HTMLInputElement>(null),
    email: useRef<HTMLInputElement>(null),
    password: useRef<HTMLInputElement>(null),
    confirmation: useRef<HTMLInputElement>(null),
  };

  function validate(next: Record<Field, string>): FieldErrors {
    return {
      displayName: validateDisplayName(next.displayName),
      email: validateEmail(next.email),
      password: validatePassword(next.password),
      confirmation: validatePasswordConfirmation(next.password, next.confirmation),
    };
  }

  function update(field: Field, value: string) {
    const next = { ...values, [field]: value };
    setValues(next);
    // İlk gönderim denemesinden sonra hatalar yazarken güncellenir.
    if (errors) setErrors(validate(next));
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    setSubmitError(null);

    const nextErrors = validate(values);
    setErrors(nextErrors);
    const firstInvalid = FIELD_ORDER.find((field) => nextErrors[field]);
    if (firstInvalid) {
      refs[firstInvalid].current?.focus();
      return;
    }

    setSubmitting(true);
    try {
      const result = await service.signUp({
        displayName: values.displayName.trim(),
        email: values.email.trim(),
        password: values.password,
      });
      if (result.status === "verification_required") {
        setPendingEmail(values.email.trim());
        navigate("/demo/verify-email");
      }
    } catch {
      setSubmitError("Demo kayıt işlemi tamamlanamadı. Lütfen tekrar deneyin.");
      setSubmitting(false);
    }
  }

  return (
    <DemoAuthCard
      title="IOC Enricher — Hesap Oluştur"
      description={
        <p>
          Bu form gerçek bir hesap oluşturmaz. Girdiğiniz parola saklanmaz ve
          hiçbir yere gönderilmez; sonraki adımda e-posta doğrulama ekranının
          demo sürümü açılır.
        </p>
      }
      footer={
        <>
          Zaten hesabınız var mı?{" "}
          <Link to="/demo/login" className={DEMO_LINK}>
            Demo girişine dön
          </Link>
        </>
      }
    >
      <form className="space-y-4" onSubmit={handleSubmit} noValidate>
        <DemoTextField
          id="signup-display-name"
          label="Görünen ad"
          autoComplete="name"
          maxLength={DISPLAY_NAME_MAX_LENGTH}
          value={values.displayName}
          onChange={(v) => update("displayName", v)}
          error={errors?.displayName}
          inputRef={refs.displayName}
        />
        <DemoTextField
          id="signup-email"
          label="E-posta"
          type="email"
          autoComplete="email"
          maxLength={EMAIL_MAX_LENGTH}
          value={values.email}
          onChange={(v) => update("email", v)}
          error={errors?.email}
          inputRef={refs.email}
        />
        <div>
          <DemoTextField
            id="signup-password"
            label="Parola"
            type="password"
            autoComplete="new-password"
            maxLength={PASSWORD_MAX_LENGTH}
            value={values.password}
            onChange={(v) => update("password", v)}
            error={errors?.password}
            describedBy="signup-password-requirements"
            inputRef={refs.password}
          />
          <PasswordRequirementList
            id="signup-password-requirements"
            password={values.password}
          />
        </div>
        <DemoTextField
          id="signup-password-confirmation"
          label="Parola tekrarı"
          type="password"
          autoComplete="new-password"
          maxLength={PASSWORD_MAX_LENGTH}
          value={values.confirmation}
          onChange={(v) => update("confirmation", v)}
          error={errors?.confirmation}
          inputRef={refs.confirmation}
        />

        <p className="rounded-md border border-dashed border-surface-border px-3 py-2 text-[11px] text-slate-500">
          Kullanım koşulları ve gizlilik politikası bağlantıları burada yer
          alacak (yer tutucu — belgeler henüz hazırlanmadı).
        </p>

        {submitError ? (
          <p role="alert" className={DEMO_ALERT}>
            {submitError}
          </p>
        ) : null}

        <button type="submit" disabled={submitting} className={DEMO_PRIMARY_BUTTON}>
          {submitting ? "Demo kaydı işleniyor…" : "Hesap oluştur"}
        </button>
      </form>
    </DemoAuthCard>
  );
}
