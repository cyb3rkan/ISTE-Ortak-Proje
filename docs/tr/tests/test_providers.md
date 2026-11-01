# test_providers

## 1. Amaç

`ioc_enricher/tests/test_providers.py`, sağlayıcı yeteneklerini, yanıt
ayrıştırmayı ve HTTPS zorunluluğunu denetler. Ayrıntılı sözleşmeler ve
sınırlar `test_provider_contracts.py` ve `test_provider_limits.py`
içindedir. Bkz. [Sağlayıcı Genel Bakışı](../providers/overview.md).

---

## 2. Çalıştırma

Depo kökünden, editable kurulumdan sonra:

```bash
python -m pytest ioc_enricher/tests/test_providers.py -v
python -m pytest ioc_enricher/tests/test_providers.py -k "VirusTotal" -v
python -m pytest ioc_enricher/tests/test_provider_contracts.py ioc_enricher/tests/test_provider_limits.py -v
```

---

## 3. Kapsam

`test_providers.py` (21 test fonksiyonu):

| Sınıf | Testler | Denetim |
|---|---|---|
| `TestProviderCapabilities` | `test_virustotal_supports_ip`, `test_virustotal_supports_hash`, `test_abuseipdb_supports_ip_only`, `test_shodan_supports_domain`, `test_zerobounce_supports_email_only`, `test_greynoise_supports_ip_only` | `SUPPORTED_IOC_TYPES` |
| `TestVirusTotalProvider` | `test_lookup_ip_success`, `test_lookup_ip_rate_limited`, `test_lookup_ip_not_found`, `test_lookup_hash_success`, `test_lookup_url_success` | Ayrıştırma, HTTP 429 → `rate_limited`, HTTP 404 → `not_found` |
| `TestAbuseIPDBProvider` | `test_lookup_ip_success`, `test_domain_not_supported` | Ayrıştırma; desteklenmeyen tür → `unsupported` |
| `TestGreyNoiseProvider` | `test_malicious_classification`, `test_riot_classification`, `test_not_found_is_no_record_not_success` | Sınıflandırmalar; kayıt yokluğu hüküm değil, `not_found` |
| `TestZeroBounceProvider` | `test_lookup_email_success`, `test_ip_not_supported` | Ayrıştırma; desteklenmeyen tür |
| `TestHTTPSEnforcement` | `test_http_url_rejected`, `test_provider_session_has_no_http_adapter`, `test_provider_rejects_http_url` | Düz HTTP URL'leri reddedilir, HTTP adapter'ı bağlanmaz |

İlgili dosyalar:

| Dosya | Sınıflar | Denetim |
|---|---|---|
| `test_provider_contracts.py` (67) | `TestResultStatesStayDistinct`, `TestFieldTypes`, sağlayıcı başına bir sözleşme sınıfı, `TestUnconfiguredProviders` | Durumlar birbirine karışmaz, tipi yanlış alanlar `None` olur, bozuk gövdeler `error` olur, yapılandırılmamış sağlayıcılar oluşturulmaz |
| `test_provider_limits.py` (42) | `TestRateLimiter`, `TestRetryAfter`, `TestHttpRetryPolicy`, `TestCircuitBreaker`, `TestRejectedApiKey`, `TestRateLimitedAnswers`, `TestRequestDeadline`, `TestGreyNoiseFallbackBudget`, `TestAggregatorLimits` | Sınırlı beklemeler, 429 duraklatmaları, yeniden denemeler, circuit breaker, 401 duraklatması, süre bütçeleri, worker havuzu |
| `test_provider_url_encoding.py` (2) | — | IOC değerlerinin sağlayıcı URL'lerinde kodlanması |

HTTP oturumu bir `MagicMock` ile değiştirilir
(`provider._session.request = MagicMock(...)`); hiçbir istek makineden
çıkmaz ve sahte anahtarlar yeterlidir.

---

## 4. İlgili Belgeler

- [Sağlayıcı Genel Bakışı](../providers/overview.md)
- [Rate Limiter, Zaman Aşımları ve Circuit Breaker](../features/rate-limiter.md)
- [Katkı § Test yazın](../development/contributing.md)
