/**
 * Demo "API Anahtarlarım" ekranındaki sağlayıcı kataloğu.
 *
 * KAYNAK (doğrulandı): backend `ioc_enricher/enricher.py::_init_providers`
 * aynı sırayla bu altı sağlayıcıyı tanımlar; adlar sağlayıcı sınıflarının
 * `name` değerleriyle, kimlikler `components/risk/ScoreBreakdown.tsx` ile aynıdır.
 * Desteklenen IOC türleri ve dokümantasyon bağlantıları
 * `ioc_enricher/providers/*.py` modül docstring'lerinden alınmıştır.
 * Yeni sağlayıcı eklemeden önce backend'de karşılığını doğrulayın.
 */

export type ProviderId = "virustotal" | "abuseipdb" | "shodan" | "otx" | "greynoise" | "zerobounce";

export interface DemoProviderInfo {
  id: ProviderId;
  name: string;
  description: string;
  iocTypes: string;
  /** Kodda doğrulanmış resmî API dokümantasyonu (anahtar alma rehberi değildir). */
  docsUrl: string;
}

export const DEMO_PROVIDERS: readonly DemoProviderInfo[] = Object.freeze([
  {
    id: "virustotal",
    name: "VirusTotal",
    description: "Dosya hash'i, URL, alan adı ve IP itibar sorguları.",
    iocTypes: "IPv4, IPv6, domain, URL, MD5, SHA1, SHA256",
    docsUrl: "https://developers.virustotal.com/reference/overview",
  },
  {
    id: "abuseipdb",
    name: "AbuseIPDB",
    description: "IP adresleri için kötüye kullanım raporları.",
    iocTypes: "IPv4, IPv6",
    docsUrl: "https://docs.abuseipdb.com/",
  },
  {
    id: "shodan",
    name: "Shodan",
    description: "İnternete açık host ve servis bilgileri.",
    iocTypes: "IPv4, IPv6, domain",
    docsUrl: "https://developer.shodan.io/api",
  },
  {
    id: "otx",
    name: "AlienVault OTX",
    description: "Topluluk tehdit istihbaratı (Open Threat Exchange) kayıtları.",
    iocTypes: "IPv4, IPv6, domain, URL, MD5, SHA1, SHA256",
    docsUrl: "https://otx.alienvault.com/api",
  },
  {
    id: "greynoise",
    name: "GreyNoise",
    description: "İnternet tarama gürültüsünü hedefli saldırılardan ayırt etmeye yardımcı olur.",
    iocTypes: "IPv4, IPv6",
    docsUrl: "https://docs.greynoise.io/",
  },
  {
    id: "zerobounce",
    name: "ZeroBounce",
    description: "E-posta doğrulama: toxic, spam tuzağı ve tek kullanımlık adres tespiti, alan adı yaşı.",
    iocTypes: "e-posta",
    docsUrl: "https://www.zerobounce.net/docs/email-validation-api-quickstart/v2-validate-emails",
  },
]);

export function findDemoProvider(id: string | undefined): DemoProviderInfo | undefined {
  return DEMO_PROVIDERS.find((provider) => provider.id === id);
}
