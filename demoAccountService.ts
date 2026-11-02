/**
 * Demo hesap akışları servis sınırı: kayıt, e-posta kodu doğrulama ve
 * parola sıfırlama.
 *
 * Ekranlar yalnızca `DemoAccountService` arayüzünü ve sonuç tiplerini bilir;
 * sonuçların nasıl üretildiği (mock senaryolar) burada kalır. Backend
 * entegrasyonunda mock, gerçek bir adaptörle değiştirilecek; endpoint
 * sözleşmesi henüz belirlenmedi ve burada uydurulmaz.
 *
 * SECURITY: Mock uygulama parola veya doğrulama kodunu saklamaz, loglamaz ve
 * hiçbir sonuçta geri döndürmez. Ağ isteği yapmaz; gerçek auth servislerini
 * veya token store'u çağırmaz. Her başarı sonucu `demo: true` taşır.
 */

/**
 * Yalnızca prototip için sahte doğrulama kodu. Hiçbir e-postaya gönderilmez;
 * ekranda açıkça "demo kodu" olarak gösterilir.
 */
export const DEMO_VERIFICATION_CODE = "123456";

/** Kod tekrar gönderildiğinde başlayan bekleme süresi (saniye). */
export const DEMO_RESEND_COOLDOWN_SECONDS = 30;
/** "Bekleme süresi dolmadı" senaryosunda bildirilen kalan süre (saniye). */
export const DEMO_RATE_LIMIT_RETRY_SECONDS = 45;

// --- İstek tipleri ---------------------------------------------------------

export interface SignUpRequest {
  displayName: string;
  email: string;
  password: string;
}

export interface VerifyEmailRequest {
  email: string;
  code: string;
}

export interface PasswordResetRequest {
  email: string;
}

export interface ResetPasswordRequest {
  newPassword: string;
}

// --- Sonuç tipleri ---------------------------------------------------------

export type SignUpResult = { status: "verification_required"; demo: true };

export type VerifyEmailResult =
  | { status: "verified"; demo: true }
  | { status: "invalid_code" }
  | { status: "expired_code" };

export type ResendCodeResult =
  | { status: "sent"; demo: true; cooldownSeconds: number }
  | { status: "rate_limited"; retryAfterSeconds: number };

export type PasswordResetRequestResult =
  | { status: "accepted"; demo: true }
  | { status: "unavailable" };

export type ResetPasswordResult =
  | { status: "password_updated"; demo: true }
  | { status: "link_expired" };

export interface DemoAccountService {
  signUp(request: SignUpRequest): Promise<SignUpResult>;
  verifyEmail(request: VerifyEmailRequest): Promise<VerifyEmailResult>;
  resendVerificationCode(email: string): Promise<ResendCodeResult>;
  requestPasswordReset(request: PasswordResetRequest): Promise<PasswordResetRequestResult>;
  resetPassword(request: ResetPasswordRequest): Promise<ResetPasswordResult>;
}

// --- Geliştirici demo paneli senaryoları ----------------------------------

export interface DemoAccountScenarios {
  /** `match`: yalnızca demo kodu kabul edilir; diğerleri sabit sonuç verir. */
  verifyCode: "match" | "invalid" | "expired";
  resendCode: "sent" | "rate_limited";
  passwordResetRequest: "accepted" | "unavailable";
  passwordReset: "password_updated" | "link_expired";
}

export const DEFAULT_DEMO_SCENARIOS: DemoAccountScenarios = {
  verifyCode: "match",
  resendCode: "sent",
  passwordResetRequest: "accepted",
  passwordReset: "password_updated",
};

// --- Mock uygulama --------------------------------------------------------

interface MockOptions {
  getScenarios: () => DemoAccountScenarios;
  /** Yükleniyor durumunu görünür kılmak için yapay gecikme (ms). */
  delayMs?: number;
}

function wait(ms: number): Promise<void> {
  return ms > 0 ? new Promise((resolve) => setTimeout(resolve, ms)) : Promise.resolve();
}

export function createMockDemoAccountService({
  getScenarios,
  delayMs = 300,
}: MockOptions): DemoAccountService {
  return {
    async signUp() {
      // Parola ve e-posta burada tutulmaz; gerçek hesap oluşturulmaz.
      await wait(delayMs);
      return { status: "verification_required", demo: true };
    },

    async verifyEmail({ code }) {
      await wait(delayMs);
      const scenario = getScenarios().verifyCode;
      if (scenario === "expired") return { status: "expired_code" };
      if (scenario === "match" && code === DEMO_VERIFICATION_CODE) {
        return { status: "verified", demo: true };
      }
      return { status: "invalid_code" };
    },

    async resendVerificationCode() {
      await wait(delayMs);
      if (getScenarios().resendCode === "rate_limited") {
        return { status: "rate_limited", retryAfterSeconds: DEMO_RATE_LIMIT_RETRY_SECONDS };
      }
      return { status: "sent", demo: true, cooldownSeconds: DEMO_RESEND_COOLDOWN_SECONDS };
    },

    async requestPasswordReset() {
      await wait(delayMs);
      return getScenarios().passwordResetRequest === "unavailable"
        ? { status: "unavailable" }
        : { status: "accepted", demo: true };
    },

    async resetPassword() {
      await wait(delayMs);
      return getScenarios().passwordReset === "link_expired"
        ? { status: "link_expired" }
        : { status: "password_updated", demo: true };
    },
  };
}
