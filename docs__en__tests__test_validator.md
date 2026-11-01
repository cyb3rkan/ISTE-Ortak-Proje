# test_validator

## 1. Purpose

`ioc_enricher/tests/test_validator.py` checks refanging (`sanitize_ioc`),
type detection and validation (`IOCValidator`) — the gate every IOC passes
before a provider is called. See [IOC Validation](../features/ioc-validation.md).

---

## 2. Run

From the repository root, after the editable install (see the README,
"Running the tests"):

```bash
python -m pytest ioc_enricher/tests/test_validator.py -v
python -m pytest ioc_enricher/tests/test_validator.py -k "refang" -v
python -m pytest "ioc_enricher/tests/test_validator.py::TestTypeCheckers" -v
```

---

## 3. What is covered (38 test functions)

| Class | Tests | Checks |
|---|---|---|
| `TestSanitizeIOC` | `test_refang_hxxp`, `test_refang_hxxps`, `test_refang_bracket_dot`, `test_refang_dot_word`, `test_refang_at`, `test_refang_at_word`, `test_strips_whitespace`, `test_clean_passthrough` | Each defang pattern, whitespace stripping, clean input unchanged |
| `TestIOCTypeDetection` | `test_detect_valid`, `test_detect_unknown` | `identify()` for every supported type and for junk |
| `TestIOCValidation` | `test_valid_ip_returns_ioc`, `test_invalid_ioc_returns_error`, `test_empty_returns_error`, `test_whitespace_only_returns_error`, `test_too_long_returns_error`, `test_ioc_is_immutable` | `(IOC, None)` / `(None, error)` contract, empty and over-long input, frozen `IOC` |
| `TestTypeCheckers` | `test_is_ipv4_valid`, `test_is_ipv4_invalid`, `test_is_ipv6_valid`, `test_is_md5_valid`, `test_is_md5_wrong_length`, `test_is_sha1_valid`, `test_is_sha256_valid`, `test_is_url_http`, `test_is_url_https`, `test_is_url_ftp_invalid`, `test_is_email_valid`, `test_is_email_no_tld`, `test_is_domain_valid`, `test_is_domain_single_label`, `test_is_domain_too_long` | The individual type checkers, including rejected `ftp://`, missing TLD and over-long domains |
| `TestRefangIgnoresCase` | `test_mixed_case_defang_patterns`, `test_the_rest_of_the_value_keeps_its_case`, `test_refanged_values_keep_the_detection_order` | Defang patterns in any letter case (`HXXPS://`, `[DOT]`); the rest of the value keeps its case; refanged values get the same type |
| `TestInvisibleCharactersAreRejected` | `test_url_with_a_control_or_format_character_is_rejected`, `test_other_ioc_types_are_rejected_with_the_same_reason`, `test_the_error_message_does_not_echo_the_value`, `test_ordinary_unicode_urls_stay_valid` | Control, bidi, zero-width, BOM and line-separator characters are rejected for every IOC type without echoing the value; ordinary Unicode URLs stay valid |

The tests are pure functions: no network, no files, no keys.

---

## 4. Related tests

- `tests/cli/test_terminal_output.py` — control and bidi characters in
  provider text and in rejected input are neutralised on output; evidence
  lines and colour rules in every CLI format.
- `ioc_enricher/tests/test_provider_url_encoding.py` — IOC values are encoded
  before they go into provider URLs.

---

## 5. Related

- [IOC Validation](../features/ioc-validation.md)
- [CLI Usage](../cli/usage.md)
