# Rate Limiter, Zaman Aşımları ve Circuit Breaker

## 1. Genel Bakış

Sağlayıcı çağrıları sağlayıcı başına bir **token bucket** ile hızlandırılır
(`utils/rate_limiter.py`); istek başına zaman aşımları ve IOC başına bir süre
bütçesiyle sınırlanır, sağlayıcı başına bir circuit breaker ile korunur
(`providers/base.py`). Bunların hiçbiri sınırsız beklemez: bir sağlayıcı
zamanında çağrılamıyorsa sonuç bunu söyler (`rate_limited`, `timeout` veya
`error`) ve zenginleştirme diğer sağlayıcılarla devam eder.

Burada anlatılan davranışı `ioc_enricher/tests/test_provider_limits.py`
kapsar.

---

## 2. Token bucket'lar

Her sağlayıcının, sürecin tüm iş parçacıklarınca paylaşılan tek bir bucket'ı
vardır. Çağıran token'ını bucket kilidi altında ayırır, sırasını kilidin
**dışında** bekler; böylece eşzamanlı çağıranlar birer token ile sıraya girer.

| Sağlayıcı | İstek/dakika | Burst |
|---|---|---|
| VirusTotal | 4 | 4 |
| AbuseIPDB | 60 | 10 |
| Shodan | 60 | 10 |
| AlienVault OTX | 60 | 10 |
| GreyNoise | 60 | 10 |
| ZeroBounce | 60 | 10 |
| diğer adlar | 30 | 5 |

Bunlar sağlayıcının abonelik kotası değil, bu sürecin hız bütçesidir.
VirusTotal'ın 4/dk değeri genel (ücretsiz) API hızıdır; diğerleri proje
varsayılanlarıdır. Günlük veya haftalık kotalar modellenmez: biri bittiğinde
sağlayıcı HTTP 429 döner (bkz. bölüm 4).

### Hız ayarlarını değiştirmek

```bash
# Ad=dakikadaki_istek[:burst]; girdiler ';' ile ayrılır
PROVIDER_RATE_LIMITS="VirusTotal=500:10;AlienVault OTX=60:10"
```

Burst varsayılanı `min(rpm, 10)` değeridir. Geçersiz bir girdi logda uyarı
ile yok sayılır.

---

## 3. Sınırlı bekleme

`RateLimiter.wait(provider, max_wait)` bütçesinden **en fazla** o kadar uyur,
daha uzun beklemek yerine `False` döner:

- bütçe `RATE_LIMIT_MAX_WAIT_SECONDS` değeridir (varsayılan `20`) ve IOC
  süre bütçesinden önce bitecek şekilde ayrıca kısaltılır;
- bu bütçe içinde boş slot yoksa istek **gönderilmez** ve sağlayıcı sonucu
  `rate_limited` olur ("no … request slot within the wait budget; not sent").

Bu nedenle bir worker hiçbir zaman bütün bir kota penceresi boyunca bloke
kalmaz.

---

## 4. HTTP 429

HTTP 429'da sağlayıcının bucket'ı **duraklatılır** — çağıran iş parçacığı
uyumaz —; süre `Retry-After` değeridir (saniye veya HTTP tarihi), 1–3600 saniye
ile sınırlanır; başlık yoksa veya kullanılamıyorsa 60 saniyedir. O sağlayıcının
istekleri duraklamanın bitmesini yalnızca kendi bütçeleri içinde bekler; aksi
hâlde `rate_limited` döner. 429 circuit breaker'ı asla tetiklemez.

---

## 5. Zaman aşımları ve IOC başına süre bütçesi

| Ayar | Varsayılan | Etkisi |
|---|---|---|
| bağlantı zaman aşımı | 10 sn (`BaseProvider.CONNECT_TIMEOUT_SECONDS`) | TCP/TLS bağlantısı. |
| `REQUEST_TIMEOUT` | `30` | Tek bir sağlayıcı isteğinin okuma zaman aşımı. |
| `IOC_DEADLINE_SECONDS` | `60` (`0` = kapalı) | Tek bir IOC'nin sağlayıcı aşamasının süre bütçesi. |
| `MAX_CONCURRENT_REQUESTS` | `5` | Aynı anda yürüyen sağlayıcı çağrısı; aynı `IOCEnricher` örneğinin tüm zenginleştirmelerince paylaşılan tek bir worker havuzu (CLI ve web servisi birer tane kullanır). |

Süre dolduğunda yanıt vermemiş sağlayıcılar `timeout` olarak raporlanır
("No answer within the …s enrichment deadline"), gelmiş yanıtlar korunur,
kuyrukta bekleyen çağrılar iptal edilir. Yürüyen bir çağrı da aynı süreyle
sınırlıdır: rate-limit beklemesi ve HTTP zaman aşımları süre bitmeden sona
erecek şekilde kısalır, süre geçtikten sonra hiçbir istek gönderilmez. Web
batch uç noktası IOC'lerini art arda işler ve kendi toplam bütçesine
sahiptir: `IOC_WEB_BATCH_DEADLINE_SECONDS` (varsayılan `120`; compose dosyası
`25` ayarlar). Süre geçince yeni IOC başlatılmaz ve kalanlar
`deadline_exceeded` hatasıyla döner; yürümekte olan IOC tamamlanır, bu yüzden
en kötü durum bütçe artı bir IOC süresidir.

---

## 6. Yeniden denemeler ve circuit breaker

- **Yeniden deneme:** bağlanamayan veya 500, 502, 503 ya da 504 dönen
  `GET`/`POST` istekleri üstel bekleme ile en fazla 2 kez yeniden denenir
  (urllib3 `Retry(total=2, read=0, backoff_factor=1)`); okuma zaman aşımı
  yeniden denenmez — çağrı tam okuma süresini zaten beklemiştir. Yalnızca
  HTTPS uç noktaları kabul edilir.
- **Circuit breaker:** geçici hatalar sayılır — yeniden denemelerden sonra
  kalan 5xx, zaman aşımı, bağlantı hatası veya JSON olmayan 2xx gövde. Art arda
  5 hatadan sonra devre açılır; 60 saniye sonra half-open olur ve tam olarak
  bir deneme isteği geçebilir (başarı devreyi kapatır, hata yeniden açar).
  Diğer her HTTP yanıtı (400/401/403/404/422 …) sağlayıcının ulaşılabilir
  olduğunu gösterir ve sayacı sıfırlar. Devre açıkken sağlayıcı çağrılmadan
  `error` döner.
- **HTTP 401:** sağlayıcı anahtarı reddetti; 300 saniye boyunca yeniden
  sorgulanmaz.

---

## 7. Sonuç durumları

| Sağlayıcı durumu | Anlamı | Skora etkisi |
|---|---|---|
| `success` | Veriyle yanıt verdi | Kanıt katar |
| `not_found` | Yanıt verdi: bu IOC için kayıt/analiz yok | Yok — "kanıt yok", "temiz" değil |
| `rate_limited` | Gönderilmedi (bütçede slot yok) veya HTTP 429 | Yok; erişilemeyen sayılır |
| `timeout` | İstek zaman aşımı veya IOC süresi içinde yanıt yok | Yok; erişilemeyen sayılır |
| `error` | HTTP hatası, geçersiz gövde, açık devre, reddedilen anahtar | Yok; erişilemeyen sayılır |
| `unsupported` | Sağlayıcı bu IOC türünü desteklemiyor | Sayılmaz |

Erişilemeyen sağlayıcılar `risk.unavailable_providers` içinde listelenir ve
`evidence_status` değerini `partial` yapar (kanıtla yanıt veren hiç yoksa
`insufficient_data`). Bkz. [Risk Puanlama](../scoring/risk-scoring.md).

---

## 8. Limiter'ı doğrudan kullanmak

```python
from ioc_enricher.utils.rate_limiter import RateLimiter

limiter = RateLimiter()
if limiter.wait("VirusTotal"):        # False: bütçe içinde slot yok
    ...                               # isteği gönder
limiter.backoff("AbuseIPDB", 120)     # Retry-After: 120 ile gelen HTTP 429 sonrası
```

`BaseProvider` üzerine kurulan sağlayıcılar bunu otomatik yapar.

---

## 9. En iyi uygulamalar

- Genel bir anahtarda VirusTotal'ı 4/dk'da tutun; yalnızca premium bir
  anahtar için `PROVIDER_RATE_LIMITS` ile artırın.
- Art arda gelen `rate_limited` sonuçları, hız veya bekleme bütçesinin hacme
  göre dar kaldığını — ya da bir kotanın bittiğini — gösterir (logda
  "Rate limit hit for … — pausing" satırını arayın).
- Aynı IOC'lerin tekrar triage'ı için önbelleği kullanın.

---

## 10. İlgili Belgeler

- [Zenginleştirme Motoru](enrichment-engine.md)
- [Sağlayıcı Genel Bakışı](../providers/overview.md)
- [Mimari Genel Bakış](../architecture/overview.md)
