# AlienVault OTX Provider

## 1. Overview

`providers/otx.py` looks up indicators in
[AlienVault OTX](https://otx.alienvault.com/api) and reports how many
community threat "pulses" reference them. It contributes up to 15 of the 100
score points.

---

## 2. Requests

All requests use the `general` section of `https://otx.alienvault.com/api/v1/indicators/…`:

| IOC type | Path |
|---|---|
| IPv4 / IPv6 | `IPv4/{ip}/general` or `IPv6/{ip}/general` |
| Domain | `domain/{domain}/general` |
| MD5, SHA1, SHA256 | `file/{hash}/general` |
| URL | `url/{percent-encoded URL}/general` |

The key travels in the `X-OTX-API-KEY` header. Client-side pacing: 60
requests per minute, burst 10.

---

## 3. Normalised data

| IOC type | Fields |
|---|---|
| IP, domain | `pulse_count`, `pulse_references` (up to 5: pulse name, author), `reputation`, `country_code`, `country_name`, `asn`, `city`, `whois`, `alexa` |
| Hash | `pulse_count`, `file_type`, `file_class` |
| URL | `pulse_count`, `domain`, `alexa` |

`pulse_info.count` is required: an answer without it is an `error`, never
"0 pulses". The web API returns `pulse_count`, `reputation` and
`country_code`. The AI layer receives `pulse_count`, reputation, country,
ASN, `alexa` and file type/class as facts and the pulse names as quoted text;
WHOIS text never reaches the model.

---

## 4. Statuses

| Situation | Status |
|---|---|
| Answer with `pulse_info.count` (also 0) | `success` |
| HTTP 404 | `not_found` |
| `pulse_info` missing or count mistyped | `error` ("Invalid response from AlienVault OTX: …") |
| HTTP 400 (unsupported indicator), 401, 403 … | `error` (`HTTP <code>`); 401 also pauses the provider for 300 s |
| HTTP 429 | `rate_limited`, provider paused |

---

## 5. Scoring

| Pulses | Points |
|---|---|
| 0 | 0 |
| 1–2 | 5 |
| 3–5 | 9 |
| 6–10 | 12 |
| more than 10 | 15 |

For hashes with strong VirusTotal evidence, ≥ 10 / ≥ 25 pulses raise the
score floor to 85 / 90 and add detection confidence. Pulse names that
mention C2 terms (C2, C&C, command and control, botnet, Cobalt Strike,
beacon) map to MITRE T1071; a pulse count alone does not.

---

## 6. Caveats

- Zero pulses is not a clean verdict: OTX has coverage gaps, especially for
  new or niche indicators.
- Pulses are community content of varying quality; a pulse count measures
  attention, not maliciousness.

---

## 7. Related

- [Provider Overview](overview.md)
- [Risk Scoring](../scoring/risk-scoring.md)
- [MITRE Mapping](../features/mitre-mapping.md)
- [Test: test_providers](../tests/test_providers.md)
