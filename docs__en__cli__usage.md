# CLI Usage

## 1. Overview

The command-line interface (`cli/main.py`, `argparse`) enriches a single IOC
or a file of IOCs, prints or saves reports, and manages the cache:

```bash
python -m ioc_enricher [OPTIONS]
```

Examples below use documentation addresses (RFC 5737) and fake values.

---

## 2. Security notes

- No provider is queried without an explicit IOC argument.
- API keys come only from the environment or a `.env` file in the **current
  directory** (`IOC_ENRICHER_DOTENV=<path>` selects another file,
  `IOC_ENRICHER_DOTENV=0` disables it); they are never CLI arguments or
  prompts, and variables already in the environment win.
- Untrusted text — provider fields, AI output, error messages, IOCs read from
  files — is printed with terminal control characters made visible: ESC
  (CSI/OSC sequences that could clear the screen or retitle the window), BEL,
  CR, 8-bit C1 controls, bidi overrides and zero-width characters appear as
  escapes such as `\x1b` or `\u202e`. Ordinary text is unchanged. This applies
  to the terminal, table and Markdown formats; the JSON formats escape such
  characters as `\uXXXX`, so the decoded values stay identical.
- An IOC that itself contains control, bidi or zero-width characters is
  rejected before any provider call (`❌ Validation error: IOC contains
  control or invisible formatting characters.`); the message does not echo
  the value.
- Log lines go to stderr and name IOCs by a keyed fingerprint
  (`ipv4#051be4c68a3a`), never by value.
- Saved report names never contain the IOC (section 7).

---

## 3. Installation

```bash
python -m pip install -r requirements.txt   # hash-pinned lock (requirements/test.txt)
python -m pip install --no-deps -e .         # the package itself
cp .env.example .env                         # then add provider keys
python -m ioc_enricher --status
```

Python 3.11 or newer is required (`pyproject.toml`); CI and the backend image
use 3.12.

---

## 4. Command reference

### IOC input (mutually exclusive)

| Flag | Description |
|---|---|
| `--ip ADDRESS` | IPv4 or IPv6 address |
| `--domain DOMAIN` | Domain name |
| `--hash HASH` | MD5, SHA1 or SHA256 |
| `--url URL` | URL (`http://` or `https://`) |
| `--email EMAIL` | E-mail address |
| `--ioc VALUE` | Any IOC; the type is detected |
| `--file FILE` | One IOC per line (batch mode) |

### Output

| Flag | Values | Default |
|---|---|---|
| `--output` | `terminal`, `json`, `markdown`, `table`, `ndjson` | `terminal` |
| `--save` | `json`, `markdown`, `table`, `ndjson` | none |

`--output` applies to single-IOC runs; batch mode prints one summary line per
IOC.

### Cache and utilities

| Flag | Description |
|---|---|
| `--no-cache` | Bypass the cache for this run |
| `--clear-cache` | Remove cache entries and exit |
| `--cache-stats` | Print cache statistics and exit |
| `--status` | Print provider and AI key status and exit |
| `--no-banner` | Suppress the banner |
| `--version` | Print the version and exit |

---

## 5. Examples

```bash
python -m ioc_enricher --ip 203.0.113.7
python -m ioc_enricher --domain malicious.example.com
python -m ioc_enricher --hash 44d88612fea8a8f36de82e1278abb02f
python -m ioc_enricher --url "https://malicious.example.com/payload.exe"
python -m ioc_enricher --email phisher@malicious.example.com
python -m ioc_enricher --ioc 203.0.113.7            # auto-detect

# Defanged input is refanged automatically, in any letter case
python -m ioc_enricher --url "hxxps://malicious[.]example[.]com/path"
python -m ioc_enricher --url "HXXPS://malicious[DOT]example[DOT]com/path"
python -m ioc_enricher --ioc "203[.]0[.]113[.]7"

# Batch
python -m ioc_enricher --file iocs.txt --no-cache
python -m ioc_enricher --file iocs.txt --save json  # one report per IOC
```

`iocs.txt`: one IOC per line; empty lines and lines starting with `#` are
skipped.

---

## 6. Output formats

| `--output` | Content |
|---|---|
| `terminal` | Report: IOC, type, time, risk score and level, detection confidence, evidence line, reasons, "why" lines (`(AI narrative)` when model-written), human-review hint, provider results, MITRE ATT&CK, AI summary and audit line. Coloured only on an interactive terminal; plain text when piped or redirected and whenever `NO_COLOR` is set. |
| `table` | Plain-text table, no ANSI codes, with evidence rows. |
| `markdown` | Markdown report (backticks and `<>` removed from provider text), with an evidence row and, for `insufficient_data` or `partial` evidence, a note. |
| `json` | `result.to_dict()` pretty-printed. |
| `ndjson` | The same record on one line. |

Every format states how much evidence the score rests on, so a run in which
no provider returned usable data never reads as a clean `0/100 LOW`:

| Format | Shows |
|---|---|
| `terminal` | `Evidence: insufficient data — … this score is not a clean verdict.`, `Evidence: partial — 1/2 providers returned data; unavailable: …` or `Evidence: complete — …`; ❔ replaces the level mark when there is no evidence |
| `table` | `Evidence Status`, `Providers With Data`, `Unavailable Providers` rows; `No usable data; not a clean verdict` note |
| `markdown` | `Evidence Status` metric row; "Insufficient data" / "Partial coverage" note |
| `json`, `ndjson` | `evidence_status`, `provider_coverage`, `unavailable_providers` |
| `--file` batch line | `(insufficient data — not a clean verdict)` or `(partial: N provider(s) unavailable)`; ❔ instead of ✅ |

The JSON record has the top-level keys `metadata` (`ioc`, `ioc_type`,
`timestamp`, `execution_time_s`, `from_cache`), `risk_assessment` (`score`,
`level`, `detection_confidence`, `reasons`, `evidence_status`,
`provider_coverage`, `unavailable_providers`, …), `threat_intelligence`
(per-provider results), `mitre_attack` and `ai_analysis`.

**stdout is not only the report:** a single-IOC run prints
`🔍 Analysing: <ioc>` before the report and `⏱️  Completed in …s` (and
`💾 Result served from cache.` on a cache hit) after it. Extract the JSON
before piping it:

```bash
python -m ioc_enricher --no-banner --ioc 203.0.113.7 --output ndjson | grep '^{' | jq '.risk_assessment.level'
python -m ioc_enricher --no-banner --ioc 203.0.113.7 --output json | sed -n '/^{/,/^}/p' | jq '.risk_assessment.reasons[]'
```

---

## 7. Saving reports

`--save FORMAT` writes one file per enriched IOC to `Config.REPORTS_DIR`
(`ioc_enricher/reports/` in a source checkout) and prints where it went:

```
💾 Report saved: <reports dir>/ioc_ipv4_20261028T101500Z_3f9c2a1b.json
```

| Format | Extension |
|---|---|
| `json` | `.json` |
| `markdown` | `.md` |
| `table` | `.txt` |
| `ndjson` | `.ndjson` |

- Name: `ioc_<type>_<UTC time>_<8 random hex>.<ext>` — the IOC value is never
  part of the name (names end up in listings, shell history, backups).
- An existing file is never overwritten: a clash draws a new random suffix.
- Files are created owner-only on POSIX.
- CLI reports are **not** pruned automatically (`REPORT_RETENTION_DAYS`
  applies to web reports only); delete them when no longer needed.

---

## 8. Cache and status output

```
$ python -m ioc_enricher --no-banner --cache-stats
📦 Cache Statistics
───────────────────────────────────
  entry_count               142
  total_size_kb             2304.5
  ttl_hours                 24.0
  enabled                   True

$ python -m ioc_enricher --no-banner --status
📡 Provider Status
─────────────────────────────────────────────
  ✅  VirusTotal                Active
  ❌  GreyNoise                 No API key
  …
  ❌  Groq (AI layer)           No API key
```

---

## 9. Exit codes

| Code | When |
|---|---|
| `0` | Single IOC enriched (any risk level); batch finished (even if some IOCs failed — see the `❌` lines); `--status`, `--cache-stats`, `--clear-cache`, `--version` |
| `1` | No IOC given, validation error, enrichment failure, initialisation failure, `--file` missing or without IOCs |

---

## 10. Related

- [Cache System and Report Retention](../features/cache-system.md)
- [Enrichment Engine](../features/enrichment-engine.md)
- [Risk Scoring](../scoring/risk-scoring.md)
