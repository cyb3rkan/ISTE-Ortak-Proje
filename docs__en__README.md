# IOC Enricher — Documentation

> Multi-source threat intelligence enrichment for Indicators of Compromise

---

## Quick Navigation

### Architecture
- [System Overview](architecture/overview.md) — pipeline stages, component map, concurrency model

### Features
- [Enrichment Engine](features/enrichment-engine.md) — main pipeline orchestrator
- [IOC Validation](features/ioc-validation.md) — type detection, defanging, format validation
- [Cache System and Report Retention](features/cache-system.md) — file cache, size cap, report retention
- [Rate Limiter, Timeouts and Circuit Breaker](features/rate-limiter.md) — bounded waits, HTTP 429, deadlines, retries
- [MITRE ATT&CK Mapping](features/mitre-mapping.md) — heuristic technique mapping
- [AI Analysis](features/ai-analysis.md) — optional Groq narrative layer, data sent, reply validation

### Risk Scoring
- [Risk Scoring Model](scoring/risk-scoring.md) — 0–100 deterministic scoring, provider weights, thresholds

### Providers
- [Provider Overview](providers/overview.md) — capability matrix, BaseProvider architecture
- [VirusTotal](providers/virustotal.md) — multi-engine malware scanning (max 35 pts)
- [AbuseIPDB](providers/abuseipdb.md) — IP abuse confidence scoring (max 25 pts)
- [Shodan](providers/shodan.md) — device fingerprinting + CVEs (max 10 pts)
- [AlienVault OTX](providers/otx.md) — threat intelligence pulses (max 15 pts)
- [GreyNoise](providers/greynoise.md) — internet noise classification (max 10 pts)
- [ZeroBounce](providers/zerobounce.md) — email validation scoring (max 5 pts)

### CLI
- [CLI Usage](cli/usage.md) — commands, flags, output formats, batch processing

### Security
- [Security Considerations](security/considerations.md) — threat model, hardening checklist

### Tests
- [test_validator](tests/test_validator.md) — IOC type detection and validation tests
- [test_scoring](tests/test_scoring.md) — risk scoring accuracy tests
- [test_cache](tests/test_cache.md) — cache TTL and behavior tests
- [test_providers](tests/test_providers.md) — provider response parsing tests
- [test_aggregator_mitre](tests/test_aggregator_mitre.md) — aggregation and MITRE mapping tests

### Development
- [Contributing Guide](development/contributing.md) — setup, adding providers, code style

---

## Risk Score Reference

| Score | Level | Action |
|---|---|---|
| 0–20 | `LOW` | Monitor or dismiss |
| 21–50 | `MEDIUM` | Investigate |
| 51–80 | `HIGH` | Prioritize and escalate |
| 81–100 | `CRITICAL` | Immediate containment |

Default thresholds; `SCORE_LOW_MAX`, `SCORE_MEDIUM_MAX` and `SCORE_HIGH_MAX`
change them. Read a level together with `evidence_status`: `LOW` with
`partial` or `insufficient_data` evidence means "not enough evidence", not
"safe to dismiss".

---

## Provider Weight Reference

| Provider | Max Points | Primary Signal |
|---|---|---|
| VirusTotal | 35 | Engine detection ratio |
| AbuseIPDB | 25 | Abuse confidence score |
| OTX | 15 | Threat pulse count |
| Shodan | 10 | CVEs + high-risk ports |
| GreyNoise | 10 | Malicious classification |
| ZeroBounce | 5 | Toxic / spam-trap / abuse signals |

---

*For Turkish documentation see [../tr/README.md](../tr/README.md)*
