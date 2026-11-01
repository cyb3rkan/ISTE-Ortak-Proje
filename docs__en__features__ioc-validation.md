# IOC Validation

## 1. Overview

`core/validator.py` is the first stage of every enrichment: `sanitize_ioc()`
refangs the input, `IOCValidator.validate()` classifies it. Only a value that
passes is sent to a provider; anything else raises `ValueError` in
`IOCEnricher.enrich()` (web API: a validation error) before any network call.

Tests: `ioc_enricher/tests/test_validator.py`.

---

## 2. Refanging — `sanitize_ioc(raw)`

Leading and trailing whitespace is removed, then these replacements are
applied anywhere in the string, in any letter case (`hXXp://`, `HXXPS://`,
`[DOT]`, `(At)` …); the rest of the value keeps its case:

| Defanged | Becomes |
|---|---|
| `hxxps://` | `https://` |
| `hxxp://` | `http://` |
| `[.]`, `[dot]`, `(dot)` | `.` |
| `[@]`, `[at]`, `(at)` | `@` |

Other notations (for example `hxxp[:]//` or `{.}`) are not refanged and the
value is then usually rejected.

---

## 3. Classification — `IOCValidator.validate(raw)`

Returns `(IOC, None)` or `(None, error_message)`. Checks, in this order:

| Order | Type | Rule |
|---|---|---|
| — | empty | `"IOC value cannot be empty."` |
| — | length | more than 2048 characters is rejected |
| — | invisible characters | control (C0/C1, incl. ESC and tab), format (bidi overrides, zero-width, BOM), surrogate and line/paragraph-separator characters: `"IOC contains control or invisible formatting characters."` — the value is not echoed |
| 1 | IPv4 | `ipaddress.IPv4Address` |
| 2 | IPv6 | `ipaddress.IPv6Address` |
| 3–5 | MD5 / SHA1 / SHA256 | 32 / 40 / 64 hexadecimal characters |
| 6 | URL | starts with `http://` or `https://` (case-insensitive) |
| 7 | E-mail | `local@domain.tld`, alphabetic TLD of at least 2 letters |
| 8 | Domain | at most 253 characters, labels of 1–63 letters/digits/hyphens, alphabetic TLD |
| — | unknown | `"'<value>' does not match any supported IOC type …"` |

`IOCValidator.identify(raw)` returns only the detected `IOCType`
(`UNKNOWN` when nothing matches).

Behaviour worth knowing (checked against the code):

- The value is not normalised: letter case is kept (`Malicious.Example.COM`
  stays as typed), so case variants are separate cache entries.
- Private, loopback and documentation addresses are valid IPs and are sent
  to the providers like any other.
- `ftp://` and other schemes are rejected; so is an e-mail address without a
  dotted domain (`user@localhost`).
- The URL rule checks the scheme; ordinary Unicode in the rest of a URL
  (`https://example.com/ürün`) stays valid, while control, bidi and
  zero-width characters are rejected by the check above. Provider and AI
  text is still neutralised on output (see
  [Security Considerations](../security/considerations.md)).

---

## 4. Examples

```python
from ioc_enricher.core.validator import IOCValidator, sanitize_ioc

ioc, error = IOCValidator.validate(sanitize_ioc("203[.]0[.]113[.]7"))
ioc.value, ioc.ioc_type.value      # ("203.0.113.7", "ipv4")

ioc, error = IOCValidator.validate(sanitize_ioc("hxxps://malicious[.]example[.]com/payload"))
ioc.value, ioc.ioc_type.value      # ("https://malicious.example.com/payload", "url")

ioc, error = IOCValidator.validate(sanitize_ioc("HXXPS://malicious[DOT]example[DOT]com/x"))
ioc.value                          # "https://malicious.example.com/x"

ioc, error = IOCValidator.validate("not-an-ioc")
ioc, error                         # (None, "'not-an-ioc' does not match any supported IOC type ...")

IOCValidator.identify("44d88612fea8a8f36de82e1278abb02f").value   # "md5"
```

CLI: `python -m ioc_enricher --ioc not-an-ioc` prints `❌ Validation error: …`
and exits with code 1.

---

## 5. Security notes

| Risk | Control | Limit |
|---|---|---|
| Oversized input | 2048-character limit (domains 253) | — |
| Injection through the IOC | Validation by type; providers receive the value in a fixed HTTPS URL or query; the URL lookups are encoded (VirusTotal URL id, OTX percent-encoding); ZeroBounce takes the email in a POST form body | A URL's path and query are not inspected |
| Terminal / display tricks | IOCs with control, bidi or zero-width characters are rejected; provider and AI text is escaped in the CLI and the UI | — |
| Accidental disclosure | — | Every valid IOC, internal ones included, is sent to each configured provider |

---

## 6. Related

- [Enrichment Engine](enrichment-engine.md)
- [CLI Usage](../cli/usage.md)
- [Security Considerations](../security/considerations.md)
- [Test: test_validator](../tests/test_validator.md)
