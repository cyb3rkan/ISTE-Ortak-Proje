import { Link } from "react-router";

import { DEMO_LINK } from "../components/DemoAuthCard";

/**
 * Demo rolünün yetmediği sayfalar için erişim reddi. Korunan sayfanın hiçbir
 * verisi yüklenmez veya render edilmez.
 */
export function DemoAccessDeniedPage() {
  return (
    <section className="mx-auto max-w-md rounded-lg border border-surface-border bg-surface-raised px-5 py-6 text-center">
      <h1 className="text-base font-semibold text-slate-100">Erişim reddedildi</h1>
      <p className="mt-2 text-sm text-slate-400">
        Bu sayfa yalnızca demo yönetici oturumunda kullanılabilir.
      </p>
      <p className="mt-1 text-xs text-slate-500">
        Not: Bu kontrol yalnızca demo arayüzündedir; gerçek sistemde yetkilendirme backend
        tarafından uygulanmalıdır.
      </p>
      <Link to="/demo/dashboard" className={`mt-4 inline-block text-sm ${DEMO_LINK}`}>
        Kontrol paneline dön
      </Link>
    </section>
  );
}
