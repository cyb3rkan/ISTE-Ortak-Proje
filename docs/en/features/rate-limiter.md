# Rate Limiter, Timeouts and Circuit Breaker

## 1. Overview

Provider calls are paced by a per-provider **token bucket**
(`utils/rate_limiter.py`), bounded by per-request timeouts and a per-IOC
deadline, and protected by a per-provider circuit breaker
(`providers/base.py`). None of these waits without limit: when a provider
cannot be called in time the result says so (`rate_limited`, `timeout` or
`error`) and the enrichment continues with the other providers.

`ioc_enricher/tests/test_provider_limits.py` covers the behaviour described
here.

---

## 2. Token buckets

Each provider has one bucket, shared by every thread of the process. A caller
reserves its token under the bucket lock and then waits for its turn
**outside** the lock, so concurrent callers queue up one token each.

| Provider | Requests/minute | Burst |
|---|---|---|
| VirusTotal | 4 | 4 |
| AbuseIPDB | 60 | 10 |
| Shodan | 60 | 10 |
| AlienVault OTX | 60 | 10 |
| GreyNoise | 60 | 10 |
| ZeroBounce | 60 | 10 |
| any other name | 30 | 5 |

These are a pacing budget for this process, not the provider's subscription
quota. VirusTotal's 4/min is the rate of its public (free) API; the others are
project defaults. Daily or weekly quotas are not modelled: when one runs out
the provider answers HTTP 429 (see section 4).

### Overriding the pacing

```bash
# Name=requests_per_minute[:burst]; entries separated by ';'
PROVIDER_RATE_LIMITS="VirusTotal=500:10;AlienVault OTX=60:10"
```

The burst defaults to `min(rpm, 10)`. An invalid entry is ignored with a
warning in the log.

---

## 3. Bounded waiting

`RateLimiter.wait(provider, max_wait)` sleeps **at most** its budget and
answers `False` instead of waiting longer:

- the budget is `RATE_LIMIT_MAX_WAIT_SECONDS` (default `20`), further
  shortened so that it ends before the IOC deadline;
- when no slot is free within that budget the request is **not sent** and the
  provider result is `rate_limited` ("no … request slot within the wait
  budget; not sent").

A worker is therefore never pinned for a whole quota window.

---

## 4. HTTP 429

On HTTP 429 the provider bucket is **paused** — the calling thread does not
sleep — for the `Retry-After` value (seconds or an HTTP date), bounded to
1–3600 seconds, or 60 seconds when the header is missing or unusable. Requests
for that provider wait for the end of the pause only within their own budget;
otherwise they answer `rate_limited`. A 429 never trips the circuit breaker.

---

## 5. Timeouts and the per-IOC deadline

| Setting | Default | Effect |
|---|---|---|
| connect timeout | 10 s (`BaseProvider.CONNECT_TIMEOUT_SECONDS`) | TCP/TLS connect. |
| `REQUEST_TIMEOUT` | `30` | Read timeout of one provider request. |
| `IOC_DEADLINE_SECONDS` | `60` (`0` = off) | Time budget of the provider phase of one IOC. |
| `MAX_CONCURRENT_REQUESTS` | `5` | Provider calls in flight at once; one worker pool shared by every enrichment of the same `IOCEnricher` (the CLI and the web service each use one). |

At the deadline, providers that have not answered are reported as `timeout`
("No answer within the …s enrichment deadline"), answers already in are kept,
and calls still queued are cancelled. A running call is bounded by the same
deadline: its rate-limit wait and HTTP timeouts shrink to end before it, and
nothing is sent once it has passed. The web batch endpoint processes its IOCs
one after another and has its own total budget,
`IOC_WEB_BATCH_DEADLINE_SECONDS` (default `120`; the compose file sets `25`):
once it has passed no new IOC is started and the remaining ones fail with
`deadline_exceeded`; an IOC already running is finished, so the worst case is
the budget plus one IOC deadline.

---

## 6. Retries and circuit breaker

- **Retries:** `GET`/`POST` requests that fail to connect or answer 500,
  502, 503 or 504 are retried up to 2 times with exponential backoff
  (urllib3 `Retry(total=2, read=0, backoff_factor=1)`); a read timeout is not
  retried — the call already waited the full read timeout. Only HTTPS
  endpoints are accepted.
- **Circuit breaker:** transient failures — a 5xx left after the retries, a
  timeout, a connection error or a non-JSON 2xx body — count. After 5
  consecutive failures the circuit opens; after 60 seconds it is half-open and
  exactly one trial request may pass (success closes it, failure re-opens it).
  Any other HTTP answer (400/401/403/404/422 …) proves the provider is
  reachable and resets the count. While open the provider answers `error`
  without being called.
- **HTTP 401:** the provider rejected the key; it is not queried again for
  300 seconds.

---

## 7. Result states

| Provider status | Meaning | Effect on the score |
|---|---|---|
| `success` | Answered with data | Contributes evidence |
| `not_found` | Answered: no record / no analysis for this IOC | None — "no evidence", not "clean" |
| `rate_limited` | Not sent (no slot in budget) or HTTP 429 | None; counted as unavailable |
| `timeout` | No answer within the request timeout or IOC deadline | None; counted as unavailable |
| `error` | HTTP error, invalid body, open circuit, rejected key | None; counted as unavailable |
| `unsupported` | Provider does not handle this IOC type | Not counted |

Unavailable providers are listed in `risk.unavailable_providers` and move
`evidence_status` to `partial` (or `insufficient_data` when nobody answered
with evidence). See [Risk Scoring](../scoring/risk-scoring.md).

---

## 8. Using the limiter directly

```python
from ioc_enricher.utils.rate_limiter import RateLimiter

limiter = RateLimiter()
if limiter.wait("VirusTotal"):        # False: no slot within the budget
    ...                               # send the request
limiter.backoff("AbuseIPDB", 120)     # after HTTP 429 with Retry-After: 120
```

Providers built on `BaseProvider` do this automatically.

---

## 9. Best practices

- Keep VirusTotal at 4/min on a public key; raise it with
  `PROVIDER_RATE_LIMITS` only for a premium key.
- A burst of `rate_limited` results means the pacing or the wait budget is
  too tight for the volume — or a quota ran out (look for "Rate limit hit for …
  — pausing" in the log).
- Use the cache for repeated triage of the same IOCs.

---

## 10. Related

- [Enrichment Engine](enrichment-engine.md)
- [Provider Overview](../providers/overview.md)
- [Architecture Overview](../architecture/overview.md)
