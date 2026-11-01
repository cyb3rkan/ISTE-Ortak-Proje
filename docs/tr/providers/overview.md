# Sağlayıcı Genel Bakışı

## 1. Genel Bakış

IOC Enricher en fazla altı tehdit istihbaratı sağlayıcısını sorgular. Her biri,
API'sini çağıran, yanıtı savunmacı biçimde ayrıştıran ve normalleştirilmiş bir
`ProviderResult` döndüren bir `BaseProvider` alt sınıfıdır
(`providers/base.py`).

Bir sağlayıcı yalnızca şu durumda sorgulanır:

1. API anahtarı yapılandırılmışsa (anahtarı olmayan sağlayıcılar oluşturulmaz) ve
2. `SUPPORTED_IOC_TYPES` kümesi IOC'nin türünü içeriyorsa.

---

## 2. Tüm sağlayıcılarda ortak kontroller

| Kontrol | Davranış |
|---|---|
| Yalnızca HTTPS | HTTPS olmayan bir URL hiçbir şey gönderilmeden `error` sonucuyla reddedilir; TLS sertifikaları her zaman doğrulanır |
| Zaman aşımları | Bağlantı 10 sn, okuma `REQUEST_TIMEOUT` (30 sn); ikisi de IOC başına süreye göre kısaltılır |
| Hız sınırı | Her istek sağlayıcının bucket'ından bir token alır; sınırlı bekleme, ardından `rate_limited` ("not sent") |
| Yeniden deneme | Bağlantı hataları ve HTTP 500/502/503/504 için en fazla 2 yeniden deneme; okuma zaman aşımı yeniden denenmez |
| Circuit breaker | Art arda 5 geçici hata devreyi 60 sn açar (ardından tek deneme isteği) |
| Reddedilen anahtar | HTTP 401 sağlayıcıyı 300 sn duraklatır |
| Yanıt denetimi | JSON nesnesi olmayan veya sağlayıcının beklenen yapısını bozan bir 2xx gövde `error` olur ("Invalid response from …") |
| Hata metni | Ağ hatası mesajlarında API anahtarı `***` ile değiştirilir; web yanıtları ayrıca bir temizleyiciden geçer |

Ayrıntılar: [Rate Limiter, Zaman Aşımları ve Circuit Breaker](../features/rate-limiter.md).

---

## 3. Durum eşlemesi

| Yanıt | Durum |
|---|---|
| Beklenen veriyle 2xx | `success` |
| HTTP 404 veya sağlayıcının kendi "kayıt yok" yanıtı | `not_found` |
| HTTP 429 | `rate_limited` (sağlayıcı `Retry-After` kadar duraklatılır, 1–3600 sn, varsayılan 60) |
| Bekleme bütçesi içinde token yok | `rate_limited` (istek gönderilmedi) |
| Zaman aşımı veya IOC süresi içinde yanıt yok | `timeout` |
| Diğer 4xx (400, 401, 402, 403, 422 …), yeniden denemeden sonra 5xx, geçersiz gövde, ağ hatası, açık devre | `error` |
| Sağlayıcının desteklemediği bir tür için arama | `unsupported` |

`not_found` "temiz" değil, "kanıt yok" demektir; `error`, `timeout` ve
`rate_limited` sağlayıcıyı bu IOC için erişilemez yapar (bkz.
[Risk Puanlama § Kanıt durumu](../scoring/risk-scoring.md)).

---

## 4. Yetenekler

| Sağlayıcı | IPv4 | IPv6 | Alan adı | URL | MD5 | SHA1 | SHA256 | E-posta | Maks. puan |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| [VirusTotal](virustotal.md) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 35 |
| [AbuseIPDB](abuseipdb.md) | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 25 |
| [Shodan](shodan.md) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | 10 |
| [AlienVault OTX](otx.md) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 15 |
| [GreyNoise](greynoise.md) | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 10 |
| [ZeroBounce](zerobounce.md) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | 5 |

---

## 5. Yapılandırma ve hız

| Sağlayıcı | Anahtar değişkeni | Anahtar nasıl gönderilir | İstemci tarafı hız (varsayılan) |
|---|---|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` | `x-apikey` başlığı | 4/dk, burst 4 |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | `Key` başlığı | 60/dk, burst 10 |
| Shodan | `SHODAN_API_KEY` | `key` query parametresi | 60/dk, burst 10 |
| AlienVault OTX | `OTX_API_KEY` | `X-OTX-API-KEY` başlığı | 60/dk, burst 10 |
| GreyNoise | `GREYNOISE_API_KEY` | `key` başlığı | 60/dk, burst 10 |
| ZeroBounce | `ZEROBOUNCE_API_KEY` | `api_key` POST form alanı | 60/dk, burst 10 |

Hız ayarı bu sürecin istek bütçesidir, sağlayıcının kotası değildir: planlar,
günlük veya aylık kotalar ve koşullar her sağlayıcı tarafından belirlenir ve
zamanla değişir — sağlayıcıdan kontrol edin. Biten bir kota HTTP 429
(`rate_limited`) veya sağlayıcının durum koduyla bir `error` olarak görünür.
Hız ayarını `PROVIDER_RATE_LIMITS` ile değiştirin.

---

## 6. Sağlayıcı verisi nereye gider

| Hedef | Ne |
|---|---|
| Puanlama | `success` sonuçlarının normalleştirilmiş `ProviderResult.data` değeri |
| Önbellek / CLI raporları | Normalleştirilmiş veri (API'nin gizlediği, kısaltılmış alanlar dahil: AbuseIPDB rapor yorumları, Shodan banner'ları gibi) |
| Web API `data_summary` | Yalnızca `web/mappers.py` içindeki allowlist alanları |
| AI katmanı (Groq) | Yalnızca `core/analyzer.py` içindeki allowlist olguları ve kısa alıntılanmış metinler — bkz. [AI Analizi](../features/ai-analysis.md) |

---

## 7. Temel sınıf

```
BaseProvider (providers/base.py)
├── __init__(api_key, timeout=30, rate_limiter=None)
├── SUPPORTED_IOC_TYPES: frozenset[IOCType]
├── name -> str                                  (aynı zamanda hız sınırı bucket adı)
├── _get_headers() -> dict
├── _request(method, url, *, params=None, json_body=None) -> ProviderResult
├── lookup_ip / lookup_domain / lookup_url / lookup_hash / lookup_email (value: str)
│       varsayılan: `unsupported`
└── supports(ioc_type) -> bool
```

```python
@dataclass
class ProviderResult:
    provider: str
    status: ProviderStatus      # success | not_found | rate_limited | timeout | error | unsupported
    data: dict | None           # normalleştirilmiş alanlar; bildirecek bir şey yoksa None
    error: str | None           # status != success olduğunda okunabilir neden
    response_time: float        # saniye
    timestamp: datetime         # sorgunun UTC zamanı
```

Sağlayıcı ekleme: [Katkı § Yeni Sağlayıcı Ekleme](../development/contributing.md).

---

## 8. İlgili Belgeler

- [Risk Puanlama](../scoring/risk-scoring.md)
- [Rate Limiter, Zaman Aşımları ve Circuit Breaker](../features/rate-limiter.md)
- [Mimari Genel Bakış](../architecture/overview.md)
- [Test: test_providers](../tests/test_providers.md)
