# GreyNoise Sağlayıcısı

## 1. Genel Bakış

`providers/greynoise.py`, bir IP adresinin internet arka plan gürültüsü (toplu
tarama) mi yoksa bilinen bir iş servisi (RIOT) mi olduğunu
[GreyNoise](https://docs.greynoise.io/) üzerinden sorar. Fırsatçı tarayıcıları
hedefli etkinlikten ayırmaya yardım eder ve 100 skor puanının en fazla
10'unu katar.

---

## 2. İstekler

| Uç nokta | Kullanım |
|---|---|
| `GET https://api.greynoise.io/v3/ip/{ip}` | IP Lookup (tarayıcı ve iş servisi veri kümeleri), önce denenir; IPv4 ve IPv6 |
| `GET https://api.greynoise.io/v3/community/{ip}` | Community API yedeği, yalnızca IPv4 |

Anahtar `key` başlığında gider. IP Lookup HTTP 403 döndürürse (anahtarın veya
planın IP Lookup erişimi yoksa) aynı IPv4 araması bir kez Community API'de
yeniden denenir ve sonraki aramalar bir saat boyunca doğrudan oraya gider;
bu sürede bir IPv6 adresi `error` alır, çünkü Community API onu
yanıtlayamaz. HTTP 401 anahtarın kendisinin reddedildiği anlamına gelir ve
yedeğe geçilmez. Her HTTP isteği kendi hız sınırı token'ını alır (dakikada
60, burst 10).

---

## 3. Normalleştirilmiş veri

| Alan | Anlamı |
|---|---|
| `noise`, `riot` | İnternette tarama yaparken görüldü / bilinen iş servisi (boolean, zorunlu) |
| `classification` | `benign`, `malicious`, `suspicious` veya `unknown` (diğer her şey `unknown` olur) |
| `name`, `actor`, `organization`, `category`, `tags` | İş servisi adı veya tarayıcı aktörü, metadata, en fazla 20 etiket |
| `first_seen`, `last_seen`, `country_code`, `asn`, `tor`, `vpn` | IP Lookup bağlamı |
| `link`, `message` | Community API ekleri |
| `data_source` | `ip_lookup` veya `community` |

Web API `classification`, `noise`, `riot`, `name`, `tags`, `first_seen` ve
`last_seen` döndürür. AI katmanı bayrakları, sınıflandırmayı, kategoriyi,
Tor/VPN bayraklarını, tarihleri, etiketleri, ülkeyi, ASN'yi ve veri kaynağını
olgu olarak; `name`, `actor`, `organization` alanlarını alıntı metni olarak
alır.

---

## 4. Durumlar

| Durum | Sonuç |
|---|---|
| En az bir veri kümesinde kayıt | `success` |
| HTTP 404 veya IP hiçbir veri kümesinde yok (ikisinde de `found: false`; Community: `noise` ve `riot` ikisi de false) — "GreyNoise has no record of this IP …" | `not_found` (tarama yaparken görülmedi, bilinen servis değil: iki yönde de kanıt yok) |
| Boolean olmayan bir `found`, `noise` veya `riot` bayrağı | `error` ("Invalid response from GreyNoise: …") |
| Anahtar için IP Lookup kullanılamıyorken IPv6 | `error` |
| HTTP 401, 403 (yedekten sonra), diğer 4xx/5xx | `error` (`HTTP <kod>`); 401 ayrıca sağlayıcıyı 300 sn duraklatır |
| HTTP 429 | `rate_limited`, sağlayıcı duraklatılır |

---

## 5. Puanlama

| Yanıt | Puan |
|---|---|
| `riot: true` (bilinen iş servisi) | 0, "known-benign infrastructure" gerekçesiyle |
| `classification: malicious` | 10 |
| `noise: true` (tarayıcı, zararlı değil) | 3 |
| diğer | 0 |

`malicious` sınıflandırması tespit güvenine ayrıca 0,20 ekler. RIOT olmayan
gürültü MITRE T1595 Active Scanning'e (dayanak `observed`) eşlenir.

---

## 6. Dikkat edilecekler

- "Gürültü" "güvenli" demek değildir: toplu tarama yapan biri size de
  saldırabilir.
- RIOT servisleri (CDN'ler, bulut, SaaS) kötüye kullanılabilir; 0 puan bir
  allowlist değil, bağlamdır.
- Community API daha az bağlam taşır (Tor/VPN bayrakları, aktör veya ASN
  yok).

---

## 7. İlgili Belgeler

- [Sağlayıcı Genel Bakışı](overview.md)
- [Risk Puanlama](../scoring/risk-scoring.md)
- [MITRE Eşleme](../features/mitre-mapping.md)
- [Test: test_providers](../tests/test_providers.md)
