# test_validator

## 1. Amaç

`ioc_enricher/tests/test_validator.py`, refang işlemini (`sanitize_ioc`), tür
tespitini ve doğrulamayı (`IOCValidator`) denetler — her IOC'nin bir
sağlayıcı çağrılmadan önce geçtiği kapı. Bkz. [IOC Doğrulama](../features/ioc-validation.md).

---

## 2. Çalıştırma

Depo kökünden, editable kurulumdan sonra (README, "Running the tests"):

```bash
python -m pytest ioc_enricher/tests/test_validator.py -v
python -m pytest ioc_enricher/tests/test_validator.py -k "refang" -v
python -m pytest "ioc_enricher/tests/test_validator.py::TestTypeCheckers" -v
```

---

## 3. Kapsam (38 test fonksiyonu)

| Sınıf | Testler | Denetim |
|---|---|---|
| `TestSanitizeIOC` | `test_refang_hxxp`, `test_refang_hxxps`, `test_refang_bracket_dot`, `test_refang_dot_word`, `test_refang_at`, `test_refang_at_word`, `test_strips_whitespace`, `test_clean_passthrough` | Her defang kalıbı, boşluk temizleme, temiz girdinin değişmemesi |
| `TestIOCTypeDetection` | `test_detect_valid`, `test_detect_unknown` | Desteklenen her tür ve anlamsız girdi için `identify()` |
| `TestIOCValidation` | `test_valid_ip_returns_ioc`, `test_invalid_ioc_returns_error`, `test_empty_returns_error`, `test_whitespace_only_returns_error`, `test_too_long_returns_error`, `test_ioc_is_immutable` | `(IOC, None)` / `(None, hata)` sözleşmesi, boş ve aşırı uzun girdi, frozen `IOC` |
| `TestTypeCheckers` | `test_is_ipv4_valid`, `test_is_ipv4_invalid`, `test_is_ipv6_valid`, `test_is_md5_valid`, `test_is_md5_wrong_length`, `test_is_sha1_valid`, `test_is_sha256_valid`, `test_is_url_http`, `test_is_url_https`, `test_is_url_ftp_invalid`, `test_is_email_valid`, `test_is_email_no_tld`, `test_is_domain_valid`, `test_is_domain_single_label`, `test_is_domain_too_long` | Tek tek tür denetleyicileri; reddedilen `ftp://`, eksik TLD ve aşırı uzun alan adları dahil |
| `TestRefangIgnoresCase` | `test_mixed_case_defang_patterns`, `test_the_rest_of_the_value_keeps_its_case`, `test_refanged_values_keep_the_detection_order` | Her harf büyüklüğünde defang kalıpları (`HXXPS://`, `[DOT]`); değerin geri kalanı harf büyüklüğünü korur; refang edilen değer aynı türü alır |
| `TestInvisibleCharactersAreRejected` | `test_url_with_a_control_or_format_character_is_rejected`, `test_other_ioc_types_are_rejected_with_the_same_reason`, `test_the_error_message_does_not_echo_the_value`, `test_ordinary_unicode_urls_stay_valid` | Kontrol, bidi, sıfır genişlikli, BOM ve satır ayırıcı karakterler her IOC türünde, değer yansıtılmadan reddedilir; olağan Unicode URL'ler geçerli kalır |

Testler saf fonksiyonlardır: ağ, dosya veya anahtar yoktur.

---

## 4. İlgili testler

- `tests/cli/test_terminal_output.py` — sağlayıcı metnindeki ve reddedilen
  girdideki kontrol ve bidi karakterleri çıktıda etkisizleştirilir; her CLI
  biçiminde kanıt satırları ve renk kuralları.
- `ioc_enricher/tests/test_provider_url_encoding.py` — IOC değerleri
  sağlayıcı URL'lerine konmadan önce kodlanır.

---

## 5. İlgili Belgeler

- [IOC Doğrulama](../features/ioc-validation.md)
- [CLI Kullanımı](../cli/usage.md)
