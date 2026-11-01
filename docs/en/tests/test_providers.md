# test_providers

## 1. Purpose

`ioc_enricher/tests/test_providers.py` checks provider capabilities, response
parsing and HTTPS enforcement. The detailed contracts and limits live in
`test_provider_contracts.py` and `test_provider_limits.py`. See
[Provider Overview](../providers/overview.md).

---

## 2. Run

From the repository root, after the editable install:

```bash
python -m pytest ioc_enricher/tests/test_providers.py -v
python -m pytest ioc_enricher/tests/test_providers.py -k "VirusTotal" -v
python -m pytest ioc_enricher/tests/test_provider_contracts.py ioc_enricher/tests/test_provider_limits.py -v
```

---

## 3. What is covered

`test_providers.py` (21 test functions):

| Class | Tests | Checks |
|---|---|---|
| `TestProviderCapabilities` | `test_virustotal_supports_ip`, `test_virustotal_supports_hash`, `test_abuseipdb_supports_ip_only`, `test_shodan_supports_domain`, `test_zerobounce_supports_email_only`, `test_greynoise_supports_ip_only` | `SUPPORTED_IOC_TYPES` |
| `TestVirusTotalProvider` | `test_lookup_ip_success`, `test_lookup_ip_rate_limited`, `test_lookup_ip_not_found`, `test_lookup_hash_success`, `test_lookup_url_success` | Parsing, HTTP 429 → `rate_limited`, HTTP 404 → `not_found` |
| `TestAbuseIPDBProvider` | `test_lookup_ip_success`, `test_domain_not_supported` | Parsing; unsupported type → `unsupported` |
| `TestGreyNoiseProvider` | `test_malicious_classification`, `test_riot_classification`, `test_not_found_is_no_record_not_success` | Classifications; no record is `not_found`, not a verdict |
| `TestZeroBounceProvider` | `test_lookup_email_success`, `test_ip_not_supported` | Parsing; unsupported type |
| `TestHTTPSEnforcement` | `test_http_url_rejected`, `test_provider_session_has_no_http_adapter`, `test_provider_rejects_http_url` | Plain-HTTP URLs refused, no HTTP adapter mounted |

Related files:

| File | Classes | Checks |
|---|---|---|
| `test_provider_contracts.py` (67) | `TestResultStatesStayDistinct`, `TestFieldTypes`, one contract class per provider, `TestUnconfiguredProviders` | Statuses never collapse into each other, mistyped fields become `None`, broken bodies become `error`, unconfigured providers are not created |
| `test_provider_limits.py` (42) | `TestRateLimiter`, `TestRetryAfter`, `TestHttpRetryPolicy`, `TestCircuitBreaker`, `TestRejectedApiKey`, `TestRateLimitedAnswers`, `TestRequestDeadline`, `TestGreyNoiseFallbackBudget`, `TestAggregatorLimits` | Bounded waits, 429 pauses, retries, circuit breaker, 401 pause, deadlines, worker pool |
| `test_provider_url_encoding.py` (2) | — | IOC values encoded in provider URLs |

The HTTP session is replaced by a `MagicMock`
(`provider._session.request = MagicMock(...)`), so no request leaves the
machine and fake keys suffice.

---

## 4. Related

- [Provider Overview](../providers/overview.md)
- [Rate Limiter, Timeouts and Circuit Breaker](../features/rate-limiter.md)
- [Contributing § Write Tests](../development/contributing.md)
