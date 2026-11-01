# VirusTotal Sağlayıcısı

## 1. Genel Bakış

`providers/virustotal.py`, IP adreslerini, alan adlarını, URL'leri ve dosya
hash'lerini [VirusTotal v3 API](https://developers.virustotal.com/reference)
üzerinde arar ve motorların son analiz hükümlerini raporlar. 100 skor
puanının en fazla 35'ini katar.

---

## 2. İstekler

| IOC türü | İstek |
|---|---|
| IPv4, IPv6 | `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}` |
| Alan adı | `GET …/api/v3/domains/{domain}` |
| URL | `GET …/api/v3/urls/{id}` — `id`, URL'nin dolgusuz base64url kodlamasıdır |
| MD5, SHA1, SHA256 | `GET …/api/v3/files/{hash}` |

Anahtar `x-apikey` başlığında gider. Tüm aramalar salt okunurdur: analiz için
hiçbir şey gönderilmez. İstemci tarafı hız: dakikada 4 istek, burst 4 (genel
API'nin hızı; premium anahtar için `PROVIDER_RATE_LIMITS` ile artırılır).

---

## 3. Normalleştirilmiş veri

`data.attributes.last_analysis_stats` ve özniteliklerden:

| Alan | Anlamı |
|---|---|
| `malicious_count`, `suspicious_count`, `harmless_count`, `undetected_count` | Motor hüküm sayıları |
| `total_engines` | **Hüküm veren** motorlar (yukarıdaki dört sayı) — tespit oranının paydası |
| `no_result_engines` | Zaman aşımına uğrayan, başarısız olan veya türü desteklemeyen motorlar — ne temiz ne zararlı |
| `reputation`, `last_analysis_date` (epoch saniye) | VirusTotal itibarı ve analiz zamanı |
| `country`, `asn`, `as_owner`, `registrar`, `file_type`, `file_size`, `categories` | VirusTotal döndürdüğünde bağlam |
| `status`, `content_type`, `tags`, `title` | URL aramaları: son HTTP durumu, içerik türü, etiketler, sayfa başlığı |

Eksik veya tipi yanlış değerler `None` olur. Web API (`web/mappers.py`
allowlist'i) sayıları, `total_engines`, `no_result_engines`, `reputation`,
`last_analysis_date`, `country`, `asn`, `as_owner`, `categories` ve URL
alanlarını döndürür; `registrar`, `file_type` ve `file_size` CLI/önbellek
verisinde kalır. AI katmanı sayıları, itibarı, tarihleri, ülkeyi, ASN'yi,
dosya tür/boyutunu, kategorileri, URL durum/içerik türü/etiketlerini olgu
olarak; `title`, `as_owner`, `registrar` alanlarını yalnızca kısa alıntı
metni olarak alır.

---

## 4. Durumlar

| Durum | Sonuç |
|---|---|
| En az bir hüküm içeren analiz | `success` |
| HTTP 404 (hash: "File hash not found in VirusTotal database.") | `not_found` |
| Nesne biliniyor ama hiçbir motorun hükmü yok (kuyrukta, hiç analiz edilmemiş veya yalnızca sonuçsuz motorlar) | `not_found` — "VirusTotal has no completed analysis for this IOC" |
| `last_analysis_stats` eksik veya bozuk | `error` ("Invalid response from VirusTotal: …") |
| HTTP 429 | `rate_limited`, sağlayıcı duraklatılır |
| Diğer HTTP hataları, zaman aşımları, ağ hataları | bkz. [Sağlayıcı Genel Bakışı § Durum eşlemesi](overview.md) |

---

## 5. Puanlama

```
puan = int(malicious_count / total_engines × 35)
     + min(5, int(suspicious_count / total_engines × 10))
skor = min(puan, 35)
```

| Zararlı | Şüpheli | Hüküm veren motor | Puan |
|---|---|---|---|
| 0 | 0 | 70 | 0 |
| 5 | 2 | 70 | 2 |
| 12 | 3 | 70 | 6 |
| 35 | 5 | 70 | 17 |
| 70 | 0 | 70 | 35 |

`0/N` yanıtı bir gerekçe ekler ("0/N engines flagged as malicious", aksi
yöndeki sağlayıcıları anarak); hiçbir zaman "temiz" hükmü vermez. Hash
IOC'lerinde güçlü VirusTotal oranları 55/75/85 skor floor'larını (OTX
desteğiyle 90) tetikler; URL puanlaması VirusTotal tespitlerini ve
kategorilerini kullanır — bkz. [Risk Puanlama](../scoring/risk-scoring.md).

---

## 6. Dikkat edilecekler

- Yeni bir dosya veya URL'de düşük oran, motorların henüz yetişmediği
  anlamına gelebilir; `last_analysis_date` değerine bakın.
- İç bir dosyanın hash'ini aramak, VirusTotal'a birinin bu hash ile
  ilgilendiğini söyler.
- EICAR test hash'i (yüksek) skorunu korur ama bir operasyonel notla
  ("indicates working detection") bilinen test dosyası olarak işaretlenir.

---

## 7. İlgili Belgeler

- [Sağlayıcı Genel Bakışı](overview.md)
- [Risk Puanlama](../scoring/risk-scoring.md)
- [Rate Limiter, Zaman Aşımları ve Circuit Breaker](../features/rate-limiter.md)
- [Test: test_providers](../tests/test_providers.md)
