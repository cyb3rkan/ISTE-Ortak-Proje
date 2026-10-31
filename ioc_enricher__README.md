# 🔍 IOC Enricher Agent

> Threat-intelligence enrichment and deterministic risk scoring, with an optional AI narrative

The Python package behind IOC Enricher: a CLI and library that enrich IP
addresses, domains, URLs, file hashes and e-mail addresses with several
threat-intelligence providers. The web API and frontend are described in the
[repository README](../README.md); full documentation is in [`docs/`](../docs/README.md).

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Multi-provider TI** | VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, GreyNoise, ZeroBounce — queried concurrently, only those with a configured key |
| **Deterministic scoring** | 0–100 score with per-provider breakdown, reasons and an evidence status (`complete` / `partial` / `insufficient_data`) |
| **MITRE ATT&CK mapping** | Heuristic tactic/technique mapping from provider signals |
| **AI narrative layer** | Optional Groq narrative on top of the deterministic result; it never changes the score |
| **Caching** | JSON file cache with TTL, schema version and size cap |
| **Rate limiting** | Per-provider token buckets with bounded waits, HTTP 429 pauses, per-IOC deadline |
| **Log hygiene** | Rotating logs; secrets, tokens, e-mails and URL queries masked; IOCs logged as keyed fingerprints |
| **Batch mode** | IOCs from a file, one per line |
| **Report export** | JSON, Markdown, plain-text table and NDJSON report files |
| **IOC sanitisation** | Refangs defanged indicators (`hxxp://`, `[.]`, `[@]`) |

---

## 🏗️ Package layout

```
ioc_enricher/                # this directory
├── ioc_enricher/            # the package
│   ├── core/                # validator, aggregator, scoring, analyzer (AI), eicar
│   ├── providers/           # BaseProvider + six providers
│   ├── models/              # IOC, ProviderResult, RiskScore, EnrichmentResult
│   ├── mitre/               # ATT&CK mapping
│   ├── reports/             # terminal, table, Markdown, JSON, NDJSON output
│   ├── utils/               # config, logger, cache, rate limiter, file helpers
│   ├── web/                 # FastAPI web API (see the repository README)
│   ├── cli/                 # CLI entry point
│   └── enricher.py          # IOCEnricher — the pipeline
└── tests/                   # package unit tests (the web, CLI and security
                             # tests live in the repository's tests/)
```

### Pipeline

```
IOC input
   ├─▶ [1] Refang & validate        (malformed input is rejected)
   ├─▶ [2] Cache lookup             (hit: providers are not queried again)
   ├─▶ [3] Provider queries         (concurrent, rate-limited, per-IOC deadline)
   ├─▶ [4] Deterministic risk score (provider-weighted, with evidence status)
   ├─▶ [5] MITRE ATT&CK mapping     (heuristic)
   ├─▶ [6] AI narrative (optional)  (Groq; validated; deterministic fallback)
   └─▶ [7] Output / report          (terminal · table · Markdown · JSON · NDJSON)
```

---

## 🌐 Supported providers

| Provider | IOC types | Notes |
|----------|-----------|-------|
| **VirusTotal** | IP, Domain, URL, Hash | AV engine detections |
| **AbuseIPDB** | IPv4, IPv6 | Abuse reports, Tor flag |
| **Shodan** | IP, Domain | Open ports, CVE ids |
| **AlienVault OTX** | IP, Domain, URL, Hash | Threat pulses |
| **GreyNoise** | IPv4, IPv6 | Noise / malicious classification |
| **ZeroBounce** | Email | Validation status, toxic / spam-trap / abuse / disposable, domain age |

---

## ⚙️ Installation

Run from the repository root (Python 3.11 or newer):

```bash
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
.venv\Scripts\activate          # Windows

python -m pip install -r requirements.txt   # hash-pinned lock (requirements/test.txt)
python -m pip install --no-deps -e .        # the package itself

cp .env.example .env            # then add the keys you have
```

---

## 🔑 Configuration

Configuration comes from environment variables; a `.env` file in the current
directory is loaded for development (`IOC_ENRICHER_DOTENV=<path>` selects
another file, `IOC_ENRICHER_DOTENV=0` disables it; variables already set
win). Leave a key empty to disable that provider — no provider is required,
but without any key every result is `insufficient_data`.

```env
# Threat-intelligence providers
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
OTX_API_KEY=
GREYNOISE_API_KEY=
ZEROBOUNCE_API_KEY=

# Optional AI narrative layer: active only with a GROQ_API_KEY, and it sends
# IOC data to Groq (docs/en/features/ai-analysis.md). AI_PROVIDER=disabled
# keeps it off regardless of keys.
AI_PROVIDER=groq
GROQ_API_KEY=
GROQ_MODEL=openai/gpt-oss-20b

# Cache
ENABLE_CACHE=true
CACHE_TTL_HOURS=24
CACHE_MAX_SIZE_MB=100

# Logging
LOG_LEVEL=INFO
```

Templates: the repository-root [`.env.example`](../.env.example) (web,
provider and AI settings) and [`ioc_enricher/.env.example`](.env.example)
(provider, AI, cache, report retention, timeout, rate-limit and logging
settings). Every variable and its default is read in
`ioc_enricher/utils/config.py`; a `.env` is loaded only from the current
directory.

API keys are issued by the providers (VirusTotal, AbuseIPDB, Shodan,
AlienVault OTX, GreyNoise, ZeroBounce); check each provider's own site for
sign-up, terms and quotas.

---

## 🚀 Usage

```bash
python -m ioc_enricher --ip 203.0.113.7
python -m ioc_enricher --domain malicious.example.com
python -m ioc_enricher --hash 44d88612fea8a8f36de82e1278abb02f
python -m ioc_enricher --url https://malicious.example.com/payload.exe
python -m ioc_enricher --email phisher@malicious.example.com
python -m ioc_enricher --ioc 198.51.100.23          # auto-detect the type

python -m ioc_enricher --ip 203.0.113.7 --save json          # report file
python -m ioc_enricher --domain malicious.example.com --save markdown
python -m ioc_enricher --ip 203.0.113.7 --output json        # JSON on stdout
python -m ioc_enricher --file iocs.txt --save json           # batch
python -m ioc_enricher --ip 203.0.113.7 --no-cache           # skip the cache

python -m ioc_enricher --status
python -m ioc_enricher --cache-stats
python -m ioc_enricher --clear-cache
```

All flags, output formats, report names and exit codes:
[CLI usage](../docs/en/cli/usage.md).

### Example IOC file (`iocs.txt`)

```
# Lines starting with # are ignored
203.0.113.7
malicious.example.com
44d88612fea8a8f36de82e1278abb02f
hxxps://malicious[.]example[.]com/payload
phisher@malicious.example.com
```

---

## 📊 Example output

Without any provider key (colour codes removed):

```
🔍 Analysing: 203.0.113.7


══════════════════════════════════════════════════════════════════════
   🔍 IOC ENRICHMENT REPORT
══════════════════════════════════════════════════════════════════════

IOC   :  203.0.113.7
Type  :  IPV4
Time  :  2026-10-28 18:10:23 UTC

──────────────────────────────────────────────────────────────────────
🎯  RISK SCORE:  0/100  ✅  LOW
    Detection Confidence: 0%
──────────────────────────────────────────────────────────────────────

📊 PROVIDER RESULTS
──────────────────────────────────────────────────────────────────────

══════════════════════════════════════════════════════════════════════

⏱️  Completed in 0.00s
```

The terminal format does not show the evidence status: this `LOW` means "no
evidence" (`evidence_status: insufficient_data` in the JSON output), not
"clean".

---

## 📊 Risk scoring

Maximum points per provider:

| Provider | Max points | Key signal |
|----------|-----------|------------|
| VirusTotal | 35 | Malicious engine detection ratio |
| AbuseIPDB | 25 | Abuse confidence score |
| AlienVault OTX | 15 | Threat pulse count |
| Shodan | 10 | High-risk ports + CVE count |
| GreyNoise | 10 | Malicious classification |
| ZeroBounce | 5 | Toxic / spam-trap / abuse / disposable, new domain |

| Score | Risk level |
|-------|-----------|
| 0–20 | 🟢 LOW |
| 21–50 | 🟡 MEDIUM |
| 51–80 | 🟠 HIGH |
| 81–100 | 🔴 CRITICAL |

Default thresholds (`SCORE_LOW_MAX`, `SCORE_MEDIUM_MAX`, `SCORE_HIGH_MAX`).
Details, floors and URL signals: [Risk scoring](../docs/en/scoring/risk-scoring.md).

---

## 🧪 Running tests

From the repository root, after the editable install above (as CI does) or
with `PYTHONPATH=ioc_enricher`. Without either, runs that include `tests/`
work with `pytest` and `python -m pytest` alike (`tests/conftest.py` adds the
package path); for `ioc_enricher/tests` alone use plain `pytest`.

```bash
python -m pytest tests ioc_enricher/tests -q            # whole backend suite
python -m pytest ioc_enricher/tests -q                  # package tests only
python -m pytest ioc_enricher/tests/test_scoring.py -v  # one file
python -m pytest -k "virustotal" -v                     # by name

# What CI runs (coverage gate 80 %)
python -m pytest ioc_enricher/tests tests/adapter tests/cli tests/api tests/security \
  --cov=ioc_enricher --cov-report=term-missing --cov-fail-under=80 -q
```

The tests do not need API keys; provider and AI calls are mocked. They
read no `.env` and keep the app log on the console.

---

## 🔒 Security notes

1. **Keys are not CLI arguments** and are sent to providers in headers —
   except Shodan, whose API takes the key as a URL query parameter.
2. **Log masking is pattern-based** (`key=value`, Bearer/Basic, JWTs,
   e-mails, URL queries) and covers the `ioc_enricher` loggers, `urllib3` /
   `requests` (request paths redacted) and uvicorn's access line.
3. **HTTPS only** with certificate verification; a non-HTTPS provider URL is
   refused before anything is sent.
4. **Input is validated** before any provider call — IOCs with control,
   bidi or zero-width characters are rejected; terminal output escapes such
   characters in provider and AI text.
5. **Cache and report files contain investigation data** (no API keys):
   keep the directories private; CLI reports are not pruned automatically.
6. **Third-party transfer:** IOCs go to every configured provider and, when
   enabled, to Groq.

More: [Security considerations](../docs/en/security/considerations.md) and
[`SECURITY.md`](../SECURITY.md).

---

## 📄 License

MIT — see [LICENSE](../LICENSE).
