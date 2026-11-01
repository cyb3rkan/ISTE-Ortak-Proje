# GreyNoise Provider

## 1. Overview

`providers/greynoise.py` asks [GreyNoise](https://docs.greynoise.io/) whether
an IP address is internet background noise (mass scanning) or a known
business service (RIOT). It helps to separate opportunistic scanners from
targeted activity and contributes up to 10 of the 100 score points.

---

## 2. Requests

| Endpoint | Use |
|---|---|
| `GET https://api.greynoise.io/v3/ip/{ip}` | IP Lookup (scanner and business-service datasets), tried first; IPv4 and IPv6 |
| `GET https://api.greynoise.io/v3/community/{ip}` | Community API fallback, IPv4 only |

The key travels in the `key` header. When IP Lookup answers HTTP 403 (key or
plan without IP Lookup access), the same IPv4 lookup is retried once on the
Community API and later lookups go straight there for one hour; an IPv6
address then gets an `error` because the Community API cannot answer it. An
HTTP 401 means the key itself was rejected and gets no fallback. Every HTTP
request takes its own rate-limit token (60 per minute, burst 10).

---

## 3. Normalised data

| Field | Meaning |
|---|---|
| `noise`, `riot` | Seen scanning the internet / known business service (booleans, required) |
| `classification` | `benign`, `malicious`, `suspicious` or `unknown` (anything else becomes `unknown`) |
| `name`, `actor`, `organization`, `category`, `tags` | Business-service name or scanner actor, metadata, up to 20 tags |
| `first_seen`, `last_seen`, `country_code`, `asn`, `tor`, `vpn` | IP Lookup context |
| `link`, `message` | Community API extras |
| `data_source` | `ip_lookup` or `community` |

The web API returns `classification`, `noise`, `riot`, `name`, `tags`,
`first_seen` and `last_seen`. The AI layer receives the flags,
classification, category, Tor/VPN flags, dates, tags, country, ASN and data
source as facts, and `name`, `actor`, `organization` as quoted text.

---

## 4. Statuses

| Situation | Status |
|---|---|
| Record in at least one dataset | `success` |
| HTTP 404, or the IP is in neither dataset (`found: false` in both; Community: `noise` and `riot` both false) — "GreyNoise has no record of this IP …" | `not_found` (not observed scanning, not a known service: no evidence either way) |
| A `found`, `noise` or `riot` flag that is not a boolean | `error` ("Invalid response from GreyNoise: …") |
| IPv6 while IP Lookup is unavailable for the key | `error` |
| HTTP 401, 403 (after the fallback), other 4xx/5xx | `error` (`HTTP <code>`); 401 also pauses the provider for 300 s |
| HTTP 429 | `rate_limited`, provider paused |

---

## 5. Scoring

| Answer | Points |
|---|---|
| `riot: true` (known business service) | 0, with a "known-benign infrastructure" reason |
| `classification: malicious` | 10 |
| `noise: true` (scanner, not malicious) | 3 |
| otherwise | 0 |

A `malicious` classification also adds 0.20 to the detection confidence.
Noise without RIOT maps to MITRE T1595 Active Scanning (basis `observed`).

---

## 6. Caveats

- "Noise" is not "safe": a mass scanner can still attack you.
- RIOT services (CDNs, cloud, SaaS) can be abused; 0 points is context, not
  an allow-list.
- The Community API carries less context (no Tor/VPN flags, actor or ASN).

---

## 7. Related

- [Provider Overview](overview.md)
- [Risk Scoring](../scoring/risk-scoring.md)
- [MITRE Mapping](../features/mitre-mapping.md)
- [Test: test_providers](../tests/test_providers.md)
