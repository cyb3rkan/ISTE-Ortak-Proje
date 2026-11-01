# Shodan Sağlayıcısı

## 1. Genel Bakış

`providers/shodan.py`, internete açık bir hostun neyi açığa çıkardığını
[Shodan API](https://developer.shodan.io/api) üzerinden sorar: açık portlar,
servisler ve bilinen CVE kimlikleri. "Bu kötü amaçlı olarak raporlandı mı?"
değil, "ne açıkta?" sorusunu yanıtlar ve 100 skor puanının en fazla 10'unu
katar.

---

## 2. İstekler

| IOC türü | İstek |
|---|---|
| IPv4, IPv6 | `GET https://api.shodan.io/shodan/host/{ip}?key=…` |
| Alan adı | `GET https://api.shodan.io/dns/resolve?hostnames={domain}&key=…` — yalnızca çözümlenen adres döner |

Shodan API anahtarı `key` **query parametresi** olarak alır. Uygulama logu URL
query string'lerini maskeler, ancak anahtar istek URL'sinin parçasıdır (TLS'i
açan bir proxy görebilir). İstemci tarafı hız: dakikada 60 istek, burst 10.

---

## 3. Normalleştirilmiş veri

| Alan | Anlamı |
|---|---|
| `ports` | Sıralı açık portlar (zorunlu liste) |
| `vulns` | Host için raporlanan CVE kimlikleri |
| `services` | Servis başına: port, taşıma, ürün, sürüm ve 300 karaktere kısaltılmış banner |
| `hostnames`, `domains`, `country_code`, `country_name`, `city`, `isp`, `asn`, `organization`, `os`, `tags`, `last_update` | Host bağlamı |
| `resolved_ip` | Yalnızca alan adı aramaları |

Web API `ports`, `hostnames`, ülke, `org` (`organization` alanından), `isp`,
`asn`, `os`, `tags`, `vulns_count`, `last_update` ve alan adları için
`resolved_ip` döndürür — servis banner'larını (ham internet metni) asla
döndürmez. Alan adı araması yalnızca `resolved_ip` döndürür (uydurulmuş
organizasyon veya CVE sayısı yok). AI katmanı ülke, ASN, işletim sistemi,
portlar, etiketler, CVE kimlikleri ve `last_update` alanlarını olgu olarak;
`organization`/`isp` alanlarını alıntı metni olarak alır.

---

## 4. Durumlar

| Durum | Sonuç |
|---|---|
| `ports` listesi olan host kaydı | `success` |
| HTTP 404 — "IP address not found in Shodan database." | `not_found` |
| Shodan'ın çözümleyemediği alan adı — "Domain could not be resolved by Shodan." | `not_found` |
| `ports` eksik veya liste değil; çözümlenen adres dizgi değil | `error` ("Invalid response from Shodan: …") |
| HTTP 401, 402, 403 … | `error` (`HTTP <kod>`); 401 ayrıca sağlayıcıyı 300 sn duraklatır |
| HTTP 429 | `rate_limited`, sağlayıcı duraklatılır |

---

## 5. Puanlama

Yüksek riskli portlar: 21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432,
5900, 6379, 11211, 27017.

```
puan  = min(5, 2 × yüksek riskli port sayısı)
puan += min(5, 2 × CVE kimliği sayısı)
skor  = min(puan, 10)
```

Açıktaki CVE'ler ayrıca MITRE T1190'a (Exploit Public-Facing Application,
dayanak `contextual`) eşlenir.

---

## 6. Dikkat edilecekler

- `not_found` "güvenli" değil, "Shodan tarafından dizinlenmemiş" demektir.
- Shodan verisi günler veya haftalar öncesine ait olabilir (`last_update`);
  portlar ve CVE'ler ele geçirilme kanıtı değil, açıklıktır.
- Alan adı araması yalnızca adı çözümler; çözümlenen adres ayrıca
  sorgulanmaz.

---

## 7. İlgili Belgeler

- [Sağlayıcı Genel Bakışı](overview.md)
- [Risk Puanlama](../scoring/risk-scoring.md)
- [MITRE Eşleme](../features/mitre-mapping.md)
- [Test: test_providers](../tests/test_providers.md)
