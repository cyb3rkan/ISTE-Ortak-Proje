/**
 * Geliştirici demo paneli — e-posta akışlarındaki durumları denemek için
 * senaryo seçici. Gerçek kullanıcı akışının parçası değildir; güvenlik
 * kontrolü veya e-posta teslimatı yapmaz, yalnızca mock sonucu seçer.
 */

import { DEMO_VERIFICATION_CODE } from "../demoAccountService";
import type { DemoAccountScenarios } from "../demoAccountService";
import { useDemoAccountFlow } from "../useDemoAccountFlow";

type ScenarioKey = keyof DemoAccountScenarios;

const SCENARIO_FIELDS: {
  [K in ScenarioKey]: {
    label: string;
    options: { value: DemoAccountScenarios[K]; label: string }[];
  };
} = {
  verifyCode: {
    label: "Kod doğrulama sonucu",
    options: [
      { value: "match", label: "Yalnızca demo kodu geçerli" },
      { value: "invalid", label: "Hatalı kod" },
      { value: "expired", label: "Süresi dolmuş kod" },
    ],
  },
  resendCode: {
    label: "Tekrar gönderme sonucu",
    options: [
      { value: "sent", label: "Demo gönderim (geri sayım başlar)" },
      { value: "rate_limited", label: "Bekleme süresi dolmadı" },
    ],
  },
  passwordResetRequest: {
    label: "Sıfırlama talebi sonucu",
    options: [
      { value: "accepted", label: "Demo başarı" },
      { value: "unavailable", label: "Servis hatası" },
    ],
  },
  passwordReset: {
    label: "Yeni parola sonucu",
    options: [
      { value: "password_updated", label: "Demo başarı" },
      { value: "link_expired", label: "Bağlantının süresi dolmuş" },
    ],
  },
};

interface DemoDevPanelProps {
  fields: ScenarioKey[];
  /** Doğrulama ekranında sahte demo kodunu gösterir. */
  showDemoCode?: boolean;
}

export function DemoDevPanel({ fields, showDemoCode = false }: DemoDevPanelProps) {
  const { scenarios, setScenario } = useDemoAccountFlow();

  return (
    <fieldset className="mx-auto w-full max-w-md rounded-lg border border-dashed border-slate-600 px-4 pb-4 pt-2">
      <legend className="px-1 font-mono text-[11px] font-semibold uppercase tracking-wide text-slate-400">
        Geliştirici demo paneli
      </legend>
      <p className="text-xs text-slate-400">
        Yalnızca prototipteki durumları denemek içindir; gerçek uygulamada
        bulunmaz. Güvenlik kontrolü veya e-posta teslimatı yapmaz, yalnızca
        sahte sonucu seçer.
      </p>
      {showDemoCode ? (
        <p className="mt-2 text-xs text-slate-300">
          Prototip test kodu:{" "}
          <span className="font-mono font-semibold text-risk-medium">
            {DEMO_VERIFICATION_CODE}
          </span>{" "}
          <span className="text-slate-400">(sahte; hiçbir yere gönderilmedi)</span>
        </p>
      ) : null}
      <div className="mt-3 space-y-3">
        {fields.map((key) => {
          const field = SCENARIO_FIELDS[key];
          const id = `demo-scenario-${key}`;
          return (
            <div key={key}>
              <label htmlFor={id} className="text-xs font-medium text-slate-400">
                {field.label}
              </label>
              <select
                id={id}
                value={scenarios[key]}
                onChange={(e) =>
                  setScenario(key, e.target.value as DemoAccountScenarios[typeof key])
                }
                className="mt-1 w-full rounded-md border border-surface-border bg-surface px-3 py-2 text-sm text-slate-100 focus:border-accent focus:outline-hidden focus-visible:outline-2 focus-visible:outline-accent"
              >
                {field.options.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
          );
        })}
      </div>
    </fieldset>
  );
}
