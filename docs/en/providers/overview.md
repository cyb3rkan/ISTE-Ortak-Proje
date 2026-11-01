# Provider Overview

## 1. Overview

IOC Enricher queries up to six threat-intelligence providers. Each one is a
`BaseProvider` subclass (`providers/base.py`) that calls its API, parses the
answer defensively and returns a normalised `ProviderResult`.

A provider is queried only when:

1. its API key is configured (providers without a key are not created), and
2. its `SUPPORTED_IOC_TYPES` contains the IOC's type.

---

## 2. Controls shared by all providers

| Control | Behaviour |
|---|---|
| HTTPS only | A non-HTTPS URL is refused with an `error` result before anything is sent; TLS certificates are always verified |
| Timeouts | Connect 10 s, read `REQUEST_TIMEOUT` (30 s), both shortened to the per-IOC deadline |
| Rate limit | Every request takes a token from the provider's bucket; bounded wait, then `rate_limited` ("not sent") |
| Retries | Up to 2 retries for connection errors and HTTP 500/502/503/504; read timeouts are not retried |
| Circuit breaker | 5 consecutive transient failures open the circuit for 60 s (then one trial request) |
| Rejected key | HTTP 401 pauses the provider for 300 s |
| Response check | A 2xx body that is not a JSON object, or breaks the provider's expected shape, becomes `error` ("Invalid response from …") |
| Error text | The API key is replaced by `***` in network error messages; web responses pass through a further sanitiser |

Details: [Rate Limiter, Timeouts and Circuit Breaker](../features/rate-limiter.md).

---

## 3. Status mapping

| Answer | Status |
|---|---|
| 2xx with the expected data | `success` |
| HTTP 404, or the provider's own "no record" answer | `not_found` |
| HTTP 429 | `rate_limited` (provider paused for `Retry-After`, 1–3600 s, default 60) |
| No token within the wait budget | `rate_limited` (request not sent) |
| Timeout, or no answer by the IOC deadline | `timeout` |
| Other 4xx (400, 401, 402, 403, 422 …), 5xx after retries, invalid body, network error, open circuit | `error` |
| Lookup for a type the provider does not support | `unsupported` |

`not_found` means "no evidence", never "clean"; `error`, `timeout` and
`rate_limited` make the provider unavailable for this IOC (see
[Risk Scoring § Evidence status](../scoring/risk-scoring.md)).

---

## 4. Capabilities

| Provider | IPv4 | IPv6 | Domain | URL | MD5 | SHA1 | SHA256 | Email | Max points |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| [VirusTotal](virustotal.md) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 35 |
| [AbuseIPDB](abuseipdb.md) | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 25 |
| [Shodan](shodan.md) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | 10 |
| [AlienVault OTX](otx.md) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 15 |
| [GreyNoise](greynoise.md) | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 10 |
| [ZeroBounce](zerobounce.md) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | 5 |

---

## 5. Configuration and pacing

| Provider | Key variable | Key sent as | Client-side pacing (default) |
|---|---|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` | `x-apikey` header | 4/min, burst 4 |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | `Key` header | 60/min, burst 10 |
| Shodan | `SHODAN_API_KEY` | `key` query parameter | 60/min, burst 10 |
| AlienVault OTX | `OTX_API_KEY` | `X-OTX-API-KEY` header | 60/min, burst 10 |
| GreyNoise | `GREYNOISE_API_KEY` | `key` header | 60/min, burst 10 |
| ZeroBounce | `ZEROBOUNCE_API_KEY` | `api_key` POST form field | 60/min, burst 10 |

Pacing is this process's request budget, not the provider's quota: plans,
daily or monthly quotas and terms are set by each provider and change over
time — check them with the provider. An exhausted quota shows up as HTTP 429
(`rate_limited`) or as an `error` with the provider's status code. Override
the pacing with `PROVIDER_RATE_LIMITS`.

---

## 6. Where provider data goes

| Destination | What |
|---|---|
| Scoring | The normalised `ProviderResult.data` of `success` results |
| Cache / CLI reports | The normalised data (including fields the API hides, such as AbuseIPDB report comments and Shodan banners, truncated) |
| Web API `data_summary` | Only the allow-listed fields in `web/mappers.py` |
| AI layer (Groq) | Only the allow-listed facts in `core/analyzer.py` plus short quoted texts — see [AI Analysis](../features/ai-analysis.md) |

---

## 7. Base class

```
BaseProvider (providers/base.py)
├── __init__(api_key, timeout=30, rate_limiter=None)
├── SUPPORTED_IOC_TYPES: frozenset[IOCType]
├── name -> str                                  (also the rate-limit bucket name)
├── _get_headers() -> dict
├── _request(method, url, *, params=None, json_body=None) -> ProviderResult
├── lookup_ip / lookup_domain / lookup_url / lookup_hash / lookup_email (value: str)
│       default: `unsupported`
└── supports(ioc_type) -> bool
```

```python
@dataclass
class ProviderResult:
    provider: str
    status: ProviderStatus      # success | not_found | rate_limited | timeout | error | unsupported
    data: dict | None           # normalised fields, None when there is nothing to report
    error: str | None           # human-readable reason when status != success
    response_time: float        # seconds
    timestamp: datetime         # UTC time of the query
```

Adding a provider: [Contributing § Adding a New Provider](../development/contributing.md).

---

## 8. Related

- [Risk Scoring](../scoring/risk-scoring.md)
- [Rate Limiter, Timeouts and Circuit Breaker](../features/rate-limiter.md)
- [Architecture Overview](../architecture/overview.md)
- [Test: test_providers](../tests/test_providers.md)
