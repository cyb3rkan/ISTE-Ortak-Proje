# AlienVault OTX Sağlayıcısı

## 1. Genel Bakış

`providers/otx.py`, göstergeleri [AlienVault OTX](https://otx.alienvault.com/api)
üzerinde arar ve kaç topluluk tehdit "pulse"unun bunlara atıf yaptığını
raporlar. 100 skor puanının en fazla 15'ini katar.

---

## 2. İstekler

Tüm istekler `https://otx.alienvault.com/api/v1/indicators/…` altındaki
`general` bölümünü kullanır:

| IOC türü | Yol |
|---|---|
| IPv4 / IPv6 | `IPv4/{ip}/general` veya `IPv6/{ip}/general` |
| Alan adı | `domain/{domain}/general` |
| MD5, SHA1, SHA256 | `file/{hash}/general` |
| URL | `url/{percent-encode edilmiş URL}/general` |

Anahtar `X-OTX-API-KEY` başlığında gider. İstemci tarafı hız: dakikada 60
istek, burst 10.

---

## 3. Normalleştirilmiş veri

| IOC türü | Alanlar |
|---|---|
| IP, alan adı | `pulse_count`, `pulse_references` (en fazla 5: pulse adı, yazar), `reputation`, `country_code`, `country_name`, `asn`, `city`, `whois`, `alexa` |
| Hash | `pulse_count`, `file_type`, `file_class` |
| URL | `pulse_count`, `domain`, `alexa` |

`pulse_info.count` zorunludur: bu alan olmayan yanıt "0 pulse" değil, `error`
olur. Web API `pulse_count`, `reputation` ve `country_code` döndürür. AI
katmanı `pulse_count`, itibar, ülke, ASN, `alexa` ve dosya tür/sınıfını olgu
olarak, pulse adlarını alıntı metni olarak alır; WHOIS metni modele asla
ulaşmaz.

---

## 4. Durumlar

| Durum | Sonuç |
|---|---|
| `pulse_info.count` içeren yanıt (0 da olsa) | `success` |
| HTTP 404 | `not_found` |
| `pulse_info` eksik veya sayının tipi yanlış | `error` ("Invalid response from AlienVault OTX: …") |
| HTTP 400 (desteklenmeyen gösterge), 401, 403 … | `error` (`HTTP <kod>`); 401 ayrıca sağlayıcıyı 300 sn duraklatır |
| HTTP 429 | `rate_limited`, sağlayıcı duraklatılır |

---

## 5. Puanlama

| Pulse | Puan |
|---|---|
| 0 | 0 |
| 1–2 | 5 |
| 3–5 | 9 |
| 6–10 | 12 |
| 10'dan fazla | 15 |

Güçlü VirusTotal kanıtı olan hash'lerde ≥ 10 / ≥ 25 pulse, skor floor'unu
85 / 90'a yükseltir ve tespit güvenini artırır. C2 terimleri (C2, C&C,
command and control, botnet, Cobalt Strike, beacon) içeren pulse adları
MITRE T1071'e eşlenir; yalnızca pulse sayısı eşlenmez.

---

## 6. Dikkat edilecekler

- Sıfır pulse temiz hüküm değildir: OTX'in kapsama boşlukları vardır,
  özellikle yeni veya niş göstergeler için.
- Pulse'lar kalitesi değişen topluluk içerikleridir; pulse sayısı kötü
  niyetliliği değil, ilgiyi ölçer.

---

## 7. İlgili Belgeler

- [Sağlayıcı Genel Bakışı](overview.md)
- [Risk Puanlama](../scoring/risk-scoring.md)
- [MITRE Eşleme](../features/mitre-mapping.md)
- [Test: test_providers](../tests/test_providers.md)
