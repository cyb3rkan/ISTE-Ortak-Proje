# AbuseIPDB Sağlayıcısı

## 1. Genel Bakış

`providers/abuseipdb.py`, IPv4 ve IPv6 adreslerini
[AbuseIPDB v2 API](https://docs.abuseipdb.com/) topluluk kötüye kullanım
raporlarına karşı denetler. 100 skor puanının en fazla 25'ini katar.

---

## 2. İstek

`GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=true`;
anahtar `Key` başlığında gider. Yalnızca son 90 günün raporları sayılır.
İstemci tarafı hız: dakikada 60 istek, burst 10.

---

## 3. Normalleştirilmiş veri

| Alan | Anlamı |
|---|---|
| `abuse_confidence_score` | 0–100 güven (zorunlu) |
| `total_reports`, `num_distinct_users`, `last_reported_at` | Rapor hacmi ve yeniliği (`total_reports` zorunlu) |
| `categories` | Dönen tüm raporlardaki farklı rapor kategori kimlikleri |
| `is_tor`, `is_public`, `is_whitelisted` | Bayraklar; AbuseIPDB bakmadıysa `is_whitelisted` `null` olur |
| `country_code`, `country_name`, `isp`, `domain`, `usage_type`, `hostnames` | Bağlam |
| `recent_reports` | En fazla 5 rapor: zaman, kategori kimlikleri, raporlayanın ülkesi ve 200 karaktere kısaltılmış yorum |

Rapor yorumları saldırganın etkileyebileceği serbest metindir: CLI/önbellek
verisinde kalır, web API tarafından **asla** döndürülmez ve AI katmanına
gönderilmez. Web API güveni, rapor sayılarını, kategorileri,
`is_public`/`is_whitelisted` bayraklarını, ülkeyi, ISP'yi, alan adını,
kullanım türünü ve son rapor zamanını döndürür. AI katmanı güveni, bayrakları
(`is_tor` dahil), sayıları, ülkeyi, kullanım türünü ve son rapor zamanını
olgu olarak; `isp` alanını alıntı metni olarak alır.

---

## 4. Durumlar

| Durum | Sonuç |
|---|---|
| `data` nesnesi, güven ve rapor sayısı içeren yanıt | `success` (temiz görünen %0 için de) |
| `data` nesnesi yok veya güven / rapor sayısı eksik ya da tipi yanlış | `error` ("Invalid response from AbuseIPDB: …") — bozuk yanıt asla %0 olarak okunmaz |
| HTTP 422 (geçersiz adres), 401, 403 … | `error` (`HTTP <kod>`); 401 ayrıca sağlayıcıyı 300 sn duraklatır |
| HTTP 429 | `rate_limited`, sağlayıcı duraklatılır |

---

## 5. Puanlama

```
puan = int(abuse_confidence_score × 0.25)
puan += 5  (is_tor ise)
skor = min(puan, 25)
```

| Güven | Tor | Puan |
|---|---|---|
| 0 | hayır | 0 |
| 40 | hayır | 10 |
| 80 | evet | 25 |
| 100 | hayır | 25 |

%0 yanıtı puan ve gerekçe eklemez; kanıt durumu için yanıt veren sağlayıcı
sayılır. Tor bayrağı MITRE eşlemesini de besler (T1090 Proxy).

---

## 6. Dikkat edilecekler

- Yüksek güven raporları yansıtır; raporlar yanlış veya eski olabilir.
  Paylaşımlı altyapı (VPN, bulut, NAT) birçok kullanıcı için rapor toplar.
- Tor çıkış düğümü bir bağlam sinyalidir, kötü amaçlı kullanımın kanıtı
  değildir.
- Bir adresi sorgulamak, AbuseIPDB'ye bu adresin incelendiğini söyler.

---

## 7. İlgili Belgeler

- [Sağlayıcı Genel Bakışı](overview.md)
- [Risk Puanlama](../scoring/risk-scoring.md)
- [MITRE Eşleme](../features/mitre-mapping.md)
- [Test: test_providers](../tests/test_providers.md)
