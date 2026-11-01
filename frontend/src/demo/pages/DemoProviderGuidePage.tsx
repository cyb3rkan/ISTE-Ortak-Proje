/**
 * Sağlayıcı API anahtarı alma rehberi (yazılı).
 *
 * Yalnızca `providerGuides.ts` içinde doğrulanmış rehberi olan sağlayıcılar
 * için adımlar gösterilir; diğerleri için adım uydurulmaz, kodda doğrulanmış
 * resmî API dokümantasyonu ve düzenlenebilir bir yer tutucu gösterilir.
 */

import { Link, useParams } from "react-router";

import { NotFoundPage } from "@/pages/NotFoundPage";
import { DEMO_LINK } from "../components/DemoAuthCard";
import { ExternalLink } from "../components/ExternalLink";
import { GuideImageSlot } from "../components/GuideImageSlot";
import { findDemoProvider } from "../demoProviders";
import { PROVIDER_GUIDES } from "../providerGuides";

export function DemoProviderGuidePage() {
  const { providerId } = useParams();
  const provider = findDemoProvider(providerId);
  if (!provider) return <NotFoundPage />;

  const guide = PROVIDER_GUIDES[provider.id];
  const backState = { focusProvider: provider.id };

  return (
    <article className="mx-auto max-w-3xl space-y-4">
      <Link to="/demo/api-keys" state={backState} className={`text-xs ${DEMO_LINK}`}>
        ← API Anahtarlarım
      </Link>

      <header>
        <h1 className="text-xl font-bold text-slate-100">
          {provider.name} API anahtarı nasıl alınır?
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Bu yazılı rehber, anahtarı sağlayıcının kendi sitesinden almanız için yol gösterir.
          IOC Enricher sizin adınıza sağlayıcıda hesap açmaz veya anahtar oluşturmaz.
        </p>
      </header>

      <section
        aria-labelledby="guide-links-title"
        className="rounded-lg border border-surface-border bg-surface-raised px-4 py-3"
      >
        <h2 id="guide-links-title" className="text-sm font-semibold text-slate-200">
          Resmî bağlantılar
        </h2>
        <ul className="mt-2 space-y-1 text-sm">
          {guide?.links.map((link) => (
            <li key={link.href}>
              <ExternalLink href={link.href}>{link.label}</ExternalLink>
            </li>
          ))}
          <li>
            <ExternalLink href={provider.docsUrl}>Resmî API dokümantasyonu</ExternalLink>
            <span className="text-xs text-slate-500"> (geliştirici dokümantasyonu)</span>
          </li>
        </ul>
      </section>

      {guide ? (
        <section aria-labelledby="guide-steps-title" className="space-y-3">
          <h2 id="guide-steps-title" className="text-sm font-semibold text-slate-200">
            Adım adım
          </h2>
          <ol aria-label="Adımlar" className="space-y-3">
            {guide.steps.map((step, index) => (
              <li
                key={step.title}
                className="rounded-lg border border-surface-border bg-surface-raised p-4"
              >
                <h3 className="flex items-baseline gap-2 text-sm font-semibold text-slate-100">
                  <span className="font-mono text-accent" aria-hidden>
                    {index + 1}.
                  </span>
                  {step.title}
                </h3>
                <p className="mt-1 text-sm text-slate-300">{step.body}</p>
                <GuideImageSlot
                  slotId={`${provider.id}-step-${index + 1}`}
                  stepNumber={index + 1}
                  image={step.image}
                />
              </li>
            ))}
          </ol>
          {guide.note ? <p className="text-xs text-slate-500">{guide.note}</p> : null}
        </section>
      ) : (
        <section className="rounded-lg border-2 border-dashed border-slate-600 px-4 py-6 text-center">
          <h2 className="text-sm font-semibold text-slate-300">Rehber yer tutucusu</h2>
          <p className="mx-auto mt-2 max-w-md text-xs text-slate-400">
            {provider.name} için anahtar alma adımları henüz yazılmadı. Adımlar ve kayıt
            bağlantısı, sağlayıcının resmî kaynaklarından doğrulandıktan sonra eklenecek.
            Şimdilik yukarıdaki resmî dokümantasyonu kullanabilirsiniz.
          </p>
        </section>
      )}

      <Link
        to="/demo/api-keys"
        state={backState}
        className="inline-flex min-h-10 items-center rounded-md bg-accent px-4 py-2 text-sm font-semibold text-slate-900 hover:bg-accent/90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
      >
        {provider.name} kartına dön
      </Link>
    </article>
  );
}
