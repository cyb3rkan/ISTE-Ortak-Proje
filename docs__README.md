# IOC Enricher — Documentation Index

Select your language / Dil seçin:

| Language | Link |
|---|---|
| English | [docs/en/README.md](en/README.md) |
| Türkçe | [docs/tr/README.md](tr/README.md) |

---

## Documentation Structure

```
docs/
├── en/                          # English documentation
│   ├── README.md                ← Start here (EN)
│   ├── architecture/
│   │   └── overview.md          System architecture & pipeline
│   ├── features/
│   │   ├── enrichment-engine.md Main pipeline orchestrator
│   │   ├── ioc-validation.md    Type detection & defanging
│   │   ├── cache-system.md      Result cache & report retention
│   │   ├── rate-limiter.md      Rate limits, timeouts, circuit breaker
│   │   ├── mitre-mapping.md     ATT&CK technique mapping
│   │   └── ai-analysis.md       Optional Groq narrative layer
│   ├── scoring/
│   │   └── risk-scoring.md      0-100 scoring model
│   ├── providers/
│   │   ├── overview.md          Capability matrix & base architecture
│   │   ├── virustotal.md
│   │   ├── abuseipdb.md
│   │   ├── shodan.md
│   │   ├── otx.md
│   │   ├── greynoise.md
│   │   └── zerobounce.md
│   ├── cli/
│   │   └── usage.md             Full CLI reference
│   ├── security/
│   │   └── considerations.md    Threat model & hardening
│   ├── tests/
│   │   ├── test_validator.md
│   │   ├── test_scoring.md
│   │   ├── test_cache.md
│   │   ├── test_providers.md
│   │   └── test_aggregator_mitre.md
│   └── development/
│       └── contributing.md      Dev setup & contribution guide
│
└── tr/                          # Türkçe belgeleme
    ├── README.md                ← Buradan başlayın (TR)
    └── [EN ile aynı yapı]
```
