# Shodan Provider

## 1. Overview

`providers/shodan.py` asks the [Shodan API](https://developer.shodan.io/api)
what an internet-facing host exposes: open ports, services and known CVE ids.
It answers "what is exposed?", not "was this reported as malicious?", and
contributes up to 10 of the 100 score points.

---

## 2. Requests

| IOC type | Request |
|---|---|
| IPv4, IPv6 | `GET https://api.shodan.io/shodan/host/{ip}?key=…` |
| Domain | `GET https://api.shodan.io/dns/resolve?hostnames={domain}&key=…` — only the resolved address is returned |

The Shodan API takes the key as the `key` **query parameter**. The
application log masks URL query strings, but the key is part of the request
URL (visible to a TLS-intercepting proxy). Client-side pacing: 60 requests
per minute, burst 10.

---

## 3. Normalised data

| Field | Meaning |
|---|---|
| `ports` | Sorted open ports (required list) |
| `vulns` | CVE ids reported for the host |
| `services` | Per service: port, transport, product, version and the banner truncated to 300 characters |
| `hostnames`, `domains`, `country_code`, `country_name`, `city`, `isp`, `asn`, `organization`, `os`, `tags`, `last_update` | Host context |
| `resolved_ip` | Domain lookups only |

The web API returns `ports`, `hostnames`, country, `org` (from
`organization`), `isp`, `asn`, `os`, `tags`, `vulns_count`, `last_update`
and, for domains, `resolved_ip` — never service banners (raw internet text).
A domain lookup returns only `resolved_ip` (no invented organisation or CVE
count). The AI layer receives country, ASN, OS, ports, tags, CVE ids and
`last_update` as facts, and `organization`/`isp` as quoted text.

---

## 4. Statuses

| Situation | Status |
|---|---|
| Host record with a `ports` list | `success` |
| HTTP 404 — "IP address not found in Shodan database." | `not_found` |
| Domain that Shodan cannot resolve — "Domain could not be resolved by Shodan." | `not_found` |
| `ports` missing or not a list; resolved address not a string | `error` ("Invalid response from Shodan: …") |
| HTTP 401, 402, 403 … | `error` (`HTTP <code>`); 401 also pauses the provider for 300 s |
| HTTP 429 | `rate_limited`, provider paused |

---

## 5. Scoring

High-risk ports: 21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 5900,
6379, 11211, 27017.

```
points  = min(5, 2 × number of high-risk ports)
points += min(5, 2 × number of CVE ids)
score   = min(points, 10)
```

Exposed CVEs also map to MITRE T1190 (Exploit Public-Facing Application,
basis `contextual`).

---

## 6. Caveats

- `not_found` means "not indexed by Shodan", not "safe".
- Shodan data can be days or weeks old (`last_update`); ports and CVEs are
  exposure, not evidence of compromise.
- A domain lookup only resolves the name; the resolved address is not
  looked up further.

---

## 7. Related

- [Provider Overview](overview.md)
- [Risk Scoring](../scoring/risk-scoring.md)
- [MITRE Mapping](../features/mitre-mapping.md)
- [Test: test_providers](../tests/test_providers.md)
