import { passwordRequirements } from "../demoValidation";

interface PasswordRequirementListProps {
  id: string;
  password: string;
}

/** Kullanıcı yazarken güncellenen parola gereksinimleri listesi. */
export function PasswordRequirementList({ id, password }: PasswordRequirementListProps) {
  const requirements = passwordRequirements(password);

  return (
    <div className="mt-2">
      <ul id={id} aria-label="Parola gereksinimleri" className="space-y-0.5 text-xs">
        {requirements.map((req) => (
          <li
            key={req.id}
            className={`flex items-center gap-1.5 ${req.met ? "text-risk-low" : "text-slate-400"}`}
          >
            <span aria-hidden className="inline-block w-3 text-center">
              {req.met ? "✓" : "○"}
            </span>
            {req.label}
            <span className="sr-only">{req.met ? " (karşılandı)" : " (karşılanmadı)"}</span>
          </li>
        ))}
      </ul>
      <p className="mt-1 text-[11px] text-slate-500">
        Prototip kuralları; gerçek parola politikası backend entegrasyonunda belirlenecek.
      </p>
    </div>
  );
}
