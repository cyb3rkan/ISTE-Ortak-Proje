# AbuseIPDB Provider

## 1. Overview

`providers/abuseipdb.py` checks IPv4 and IPv6 addresses against the
community abuse reports of the [AbuseIPDB v2 API](https://docs.abuseipdb.com/).
It contributes up to 25 of the 100 score points.

---

## 2. Request

`GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=true`
with the key in the `Key` header. Only reports from the last 90 days count.
Client-side pacing: 60 requests per minute, burst 10.

---

## 3. Normalised data

| Field | Meaning |
|---|---|
| `abuse_confidence_score` | 0–100 confidence (required) |
| `total_reports`, `num_distinct_users`, `last_reported_at` | Report volume and recency (`total_reports` required) |
| `categories` | Distinct report category ids across all returned reports |
| `is_tor`, `is_public`, `is_whitelisted` | Flags; `is_whitelisted` is `null` when AbuseIPDB did not look it up |
| `country_code`, `country_name`, `isp`, `domain`, `usage_type`, `hostnames` | Context |
| `recent_reports` | Up to 5 reports: time, category ids, reporter country and the comment truncated to 200 characters |

Report comments are attacker-influenced free text: they stay in the
CLI/cache data and are **never** returned by the web API or sent to the AI
layer. The web API returns the confidence, report counts, categories, flags
`is_public`/`is_whitelisted`, country, ISP, domain, usage type and last report
time. The AI layer receives the confidence, flags (including `is_tor`), counts,
country, usage type and last report time as facts, and `isp` as quoted text.

---

## 4. Statuses

| Situation | Status |
|---|---|
| Answer with a `data` object, confidence and report count | `success` (also for a clean-looking 0 %) |
| No `data` object, or confidence / report count missing or mistyped | `error` ("Invalid response from AbuseIPDB: …") — a broken answer is never read as 0 % |
| HTTP 422 (invalid address), 401, 403 … | `error` (`HTTP <code>`); 401 also pauses the provider for 300 s |
| HTTP 429 | `rate_limited`, provider paused |

---

## 5. Scoring

```
points = int(abuse_confidence_score × 0.25)
points += 5 if is_tor
score  = min(points, 25)
```

| Confidence | Tor | Points |
|---|---|---|
| 0 | no | 0 |
| 40 | no | 10 |
| 80 | yes | 25 |
| 100 | no | 25 |

A 0 % answer adds no points and no reason; it counts as a responding
provider for the evidence status. The Tor flag also feeds the MITRE mapping
(T1090 Proxy).

---

## 6. Caveats

- A high confidence reflects reports, which can be wrong or stale; shared
  infrastructure (VPNs, cloud, NAT) collects reports for many users.
- A Tor exit node is a context signal, not proof of malicious use.
- Querying an address tells AbuseIPDB that it is being investigated.

---

## 7. Related

- [Provider Overview](overview.md)
- [Risk Scoring](../scoring/risk-scoring.md)
- [MITRE Mapping](../features/mitre-mapping.md)
- [Test: test_providers](../tests/test_providers.md)
