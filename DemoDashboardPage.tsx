/**
 * Demo kontrol paneli — Aşama 1 iskeleti.
 *
 * Yalnızca demo oturumunu ve rol ayrımını gösterir. Hesap, API anahtarı,
 * sağlayıcı rehberi ve yönetici ekranları sonraki aşamalarda eklenecektir.
 */

import { Card } from "@/components/common/Card";
import { DEMO_ROLE_LABELS } from "../demoTypes";
import { useDemoSession } from "../useDemoSession";

const ROLE_NOTES = {
  analyst:
    "Kullanıcı görünümündesiniz. Kendi sağlayıcı anahtarlarınızı “API Anahtarlarım” sayfasından yönetebilirsiniz.",
  admin:
    "Yönetici görünümündesiniz. Demo hesap durumlarını “Kullanıcı yönetimi” sayfasından yönetebilirsiniz; yönetici, kullanıcıların API anahtarlarını veya analizlerini görmez. “API Anahtarlarım” sayfasında yalnızca kendi demo anahtarlarınız görünür.",
} as const;

export function DemoDashboardPage() {
  const { session } = useDemoSession();
  if (!session) return null;

  const { account, startedAt } = session;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Demo Kontrol Paneli</h1>
        <p className="mt-1 text-sm text-slate-400">{ROLE_NOTES[account.role]}</p>
      </div>

      <Card title="Demo oturumu">
        <dl className="grid gap-3 text-sm sm:grid-cols-3">
          <div>
            <dt className="text-xs text-slate-400">Görünen ad</dt>
            <dd className="mt-0.5 text-slate-100">{account.displayName}</dd>
          </div>
          <div>
            <dt className="text-xs text-slate-400">Rol</dt>
            <dd className="mt-0.5 text-slate-100" data-testid="demo-session-role">
              {DEMO_ROLE_LABELS[account.role]}{" "}
              <span className="font-mono text-xs text-slate-400">({account.role})</span>
            </dd>
          </div>
          <div>
            <dt className="text-xs text-slate-400">Başlangıç</dt>
            <dd className="mt-0.5 text-slate-100">
              <time dateTime={startedAt.toISOString()}>
                {startedAt.toLocaleTimeString("tr-TR")}
              </time>
            </dd>
          </div>
        </dl>
        <p className="mt-4 text-xs text-slate-400">
          Bu demo oturumu yalnızca tarayıcı belleğinde tutulur ve sayfa
          yenilendiğinde kapanır. Gerçek uygulama oturumunuz bundan etkilenmez.
        </p>
      </Card>
    </div>
  );
}
