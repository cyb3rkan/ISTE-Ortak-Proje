/**
 * Sağlayıcı API anahtarı alma rehberleri (yazılı).
 *
 * Yalnızca içeriği doğrulanmış rehberler burada yer alır. Şu an yalnızca
 * Shodan rehberi vardır; diğer sağlayıcılar için adım veya kayıt bağlantısı
 * tahmin edilmez, rehber sayfası düzenlenebilir bir yer tutucu gösterir.
 *
 * Görseller: her adımın `image` alanı şimdilik boştur ve arayüzde açıkça
 * "görsel yer tutucusu" olarak gösterilir. Gerçek ekran görüntüsü eklemek
 * için ilgili adıma `image: { src, alt }` vermek yeterlidir.
 */

import type { ProviderId } from "./demoProviders";

export interface GuideImage {
  src: string;
  alt: string;
}

export interface GuideStep {
  title: string;
  body: string;
  image?: GuideImage;
}

export interface GuideLink {
  label: string;
  href: string;
}

export interface ProviderGuide {
  providerId: ProviderId;
  links: GuideLink[];
  steps: GuideStep[];
  /** Rehber altında gösterilen kısa not. */
  note?: string;
}

export const PROVIDER_GUIDES: Partial<Record<ProviderId, ProviderGuide>> = {
  shodan: {
    providerId: "shodan",
    links: [
      { label: "Shodan hesap sayfası", href: "https://account.shodan.io" },
      {
        label: "Shodan resmî yardım sayfası",
        href: "https://help.shodan.io/developer-fundamentals/looking-up-ip-info",
      },
    ],
    steps: [
      {
        title: "Hesap oluşturun veya giriş yapın",
        body: "Shodan hesabınız yoksa Shodan hesap sayfasından bir hesap oluşturun; hesabınız varsa aynı sayfadan giriş yapın.",
      },
      {
        title: "API key alanını bulun",
        body: "Giriş yaptıktan sonra hesap sayfanızda anahtarınızın gösterildiği bölümü arayın.",
      },
      {
        title: "Anahtarı kopyalayın",
        body: "API key değerini eksiksiz kopyalayın. Anahtarı başka kişilerle paylaşmayın.",
      },
      {
        title: "IOC Enricher'a dönün",
        body: "IOC Enricher'daki “API Anahtarlarım” sayfasına geri dönün ve anahtarı Shodan kartındaki alana yapıştırın.",
      },
      {
        title: "Kaydedin",
        body: "“Anahtarı kaydet” düğmesine basın. Kayıttan sonra arayüz anahtarın tamamını yeniden göstermez; yalnızca durumu ve gerekiyorsa son birkaç karakteri gösterir.",
      },
      {
        title: "Sorun çıkarsa kontrol edin",
        body: "Anahtar çalışmazsa anahtarın doğru ve eksiksiz kopyalandığını, hesabınızdaki API erişimini ve varsa kullanım limitlerinizi kontrol edin.",
      },
      {
        title: "Hata devam ederse",
        body: "Sorun sürerse Shodan kartında görünen hata açıklamasını ve önerilen adımı takip edin.",
      },
    ],
    note: "Plan, ücret veya erişim kapsamı hakkında güncel bilgi için Shodan'ın kendi sayfalarına başvurun; bu rehber bu konularda bilgi vermez.",
  },
};
