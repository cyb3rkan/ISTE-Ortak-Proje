/**
 * Demo hesap formları için istemci tarafı doğrulama yardımcıları.
 *
 * Bunlar yalnızca kullanıcıya erken geri bildirim içindir; gerçek parola
 * politikası ve doğrulama backend entegrasyonunda belirlenecek ve sunucu
 * tarafında zorunlu tutulacaktır. Üst sınır, mevcut backend kimlik bilgisi
 * alan sınırıyla (256) uyumludur.
 */

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 256;
export const DISPLAY_NAME_MAX_LENGTH = 50;
export const EMAIL_MAX_LENGTH = 254;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export interface PasswordRequirement {
  id: string;
  label: string;
  met: boolean;
}

export function passwordRequirements(password: string): PasswordRequirement[] {
  return [
    {
      id: "length",
      label: `En az ${PASSWORD_MIN_LENGTH} karakter`,
      met: password.length >= PASSWORD_MIN_LENGTH,
    },
    { id: "letter", label: "En az bir harf", met: /\p{L}/u.test(password) },
    { id: "digit", label: "En az bir rakam", met: /\d/.test(password) },
  ];
}

export function validateDisplayName(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return "Görünen ad gerekli.";
  if (trimmed.length > DISPLAY_NAME_MAX_LENGTH) {
    return `Görünen ad en fazla ${DISPLAY_NAME_MAX_LENGTH} karakter olabilir.`;
  }
  return null;
}

export function validateEmail(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return "E-posta gerekli.";
  if (trimmed.length > EMAIL_MAX_LENGTH || !EMAIL_PATTERN.test(trimmed)) {
    return "Geçerli bir e-posta adresi girin (ör. ad@example.com).";
  }
  return null;
}

export function validatePassword(value: string): string | null {
  if (!value) return "Parola gerekli.";
  if (value.length > PASSWORD_MAX_LENGTH) {
    return `Parola en fazla ${PASSWORD_MAX_LENGTH} karakter olabilir.`;
  }
  if (passwordRequirements(value).some((req) => !req.met)) {
    return "Parola, aşağıdaki gereksinimlerin tümünü karşılamalı.";
  }
  return null;
}

export function validatePasswordConfirmation(
  password: string,
  confirmation: string,
): string | null {
  if (!confirmation) return "Parolayı tekrar girin.";
  if (password !== confirmation) return "Parolalar eşleşmiyor.";
  return null;
}

export function validateVerificationCode(value: string): string | null {
  if (!value) return "Doğrulama kodu gerekli.";
  if (!/^\d{6}$/.test(value)) return "Kod 6 haneli bir sayı olmalıdır.";
  return null;
}

/**
 * E-posta adresini kısmen maskeler: "analist@example.com" → "a***@example.com".
 * Alan adı, kullanıcının doğru adresi tanıyabilmesi için korunur.
 */
export function maskEmail(email: string): string {
  const trimmed = email.trim();
  const at = trimmed.lastIndexOf("@");
  if (at <= 0) return "***";
  return `${trimmed[0]}***${trimmed.slice(at)}`;
}
