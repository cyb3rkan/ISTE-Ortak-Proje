# VirusTotal Provider

## 1. Overview

`providers/virustotal.py` looks up IP addresses, domains, URLs and file hashes
in the [VirusTotal v3 API](https://developers.virustotal.com/reference) and
reports the engines' last-analysis verdicts. It contributes up to 35 of the
100 score points.

---

## 2. Requests

| IOC type | Request |
|---|---|
| IPv4, IPv6 | `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}` |
| Domain | `GET …/api/v3/domains/{domain}` |
| URL | `GET …/api/v3/urls/{id}` — `id` is the base64url encoding of the URL without padding |
| MD5, SHA1, SHA256 | `GET …/api/v3/files/{hash}` |

The key travels in the `x-apikey` header. All lookups are read-only: nothing
is submitted for analysis. Client-side pacing: 4 requests per minute, burst 4
(the public API's rate; `PROVIDER_RATE_LIMITS` raises it for a premium key).

---

## 3. Normalised data

From `data.attributes.last_analysis_stats` and the attributes:

| Field | Meaning |
|---|---|
| `malicious_count`, `suspicious_count`, `harmless_count`, `undetected_count` | Engine verdict counts |
| `total_engines` | Engines **with a verdict** (the four counts above) — the detection-ratio denominator |
| `no_result_engines` | Engines that timed out, failed or do not support the type — neither clean nor malicious |
| `reputation`, `last_analysis_date` (epoch seconds) | VirusTotal reputation and analysis time |
| `country`, `asn`, `as_owner`, `registrar`, `file_type`, `file_size`, `categories` | Context, when VirusTotal returns it |
| `status`, `content_type`, `tags`, `title` | URL lookups: last HTTP status, content type, tags, page title |

Missing or mistyped values are `None`. The web API (allow-list in
`web/mappers.py`) returns the counts, `total_engines`, `no_result_engines`,
`reputation`, `last_analysis_date`, `country`, `asn`, `as_owner`,
`categories` and the URL fields; `registrar`, `file_type` and `file_size`
stay in the CLI/cache data. The AI layer receives the counts, reputation, dates, country,
ASN, file type/size, categories, URL status/content type/tags as facts, and
`title`, `as_owner`, `registrar` only as short quoted text.

---

## 4. Statuses

| Situation | Status |
|---|---|
| Analysis with at least one verdict | `success` |
| HTTP 404 (hash: "File hash not found in VirusTotal database.") | `not_found` |
| Object known but no engine has a verdict (queued, never analysed, or only engines without a result) | `not_found` — "VirusTotal has no completed analysis for this IOC" |
| `last_analysis_stats` missing or malformed | `error` ("Invalid response from VirusTotal: …") |
| HTTP 429 | `rate_limited`, provider paused |
| Other HTTP errors, timeouts, network errors | see [Provider Overview § Status mapping](overview.md) |

---

## 5. Scoring

```
points = int(malicious_count / total_engines × 35)
       + min(5, int(suspicious_count / total_engines × 10))
score  = min(points, 35)
```

| Malicious | Suspicious | Engines with verdict | Points |
|---|---|---|---|
| 0 | 0 | 70 | 0 |
| 5 | 2 | 70 | 2 |
| 12 | 3 | 70 | 6 |
| 35 | 5 | 70 | 17 |
| 70 | 0 | 70 | 35 |

A `0/N` answer adds a reason ("0/N engines flagged as malicious", naming
providers that disagree), never a "clean" verdict. For hash IOCs strong
VirusTotal ratios trigger score floors of 55/75/85 (90 with OTX
corroboration), and URL scoring uses VirusTotal detections and categories —
see [Risk Scoring](../scoring/risk-scoring.md).

---

## 6. Caveats

- A low ratio on a new file or URL can simply mean the engines have not
  caught up; check `last_analysis_date`.
- Looking up a hash of an internal file tells VirusTotal that someone is
  interested in that hash.
- The EICAR test hash keeps its (high) score but is labelled a known test
  file with an operational note ("indicates working detection").

---

## 7. Related

- [Provider Overview](overview.md)
- [Risk Scoring](../scoring/risk-scoring.md)
- [Rate Limiter, Timeouts and Circuit Breaker](../features/rate-limiter.md)
- [Test: test_providers](../tests/test_providers.md)
