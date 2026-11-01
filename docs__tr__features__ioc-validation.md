# IOC Doğrulama

## 1. Genel Bakış

`core/validator.py` her zenginleştirmenin ilk aşamasıdır: `sanitize_ioc()`
girdiyi refang eder, `IOCValidator.validate()` sınıflandırır. Yalnızca geçen
değer bir sağlayıcıya gönderilir; diğer her şey herhangi bir ağ çağrısından
önce `IOCEnricher.enrich()` içinde `ValueError` fırlatır (web API: doğrulama
hatası).

Testler: `ioc_enricher/tests/test_validator.py`.

---

## 2. Refang — `sanitize_ioc(raw)`

Baştaki ve sondaki boşluklar silinir, ardından dizginin herhangi bir yerinde
şu değişiklikler harf büyüklüğü fark etmeksizin uygulanır (`hXXp://`,
`HXXPS://`, `[DOT]`, `(At)` …); değerin geri kalanı yazıldığı gibi kalır:

| Defanged | Dönüşür |
|---|---|
| `hxxps://` | `https://` |
| `hxxp://` | `http://` |
| `[.]`, `[dot]`, `(dot)` | `.` |
| `[@]`, `[at]`, `(at)` | `@` |

Diğer gösterimler (örneğin `hxxp[:]//` veya `{.}`) refang edilmez ve değer
genellikle reddedilir.

---

## 3. Sınıflandırma — `IOCValidator.validate(raw)`

`(IOC, None)` veya `(None, hata_mesajı)` döndürür. Denetimler bu sıradadır:

| Sıra | Tür | Kural |
|---|---|---|
| — | boş | `"IOC value cannot be empty."` |
| — | uzunluk | 2048 karakterden uzunu reddedilir |
| — | görünmez karakterler | kontrol (C0/C1, ESC ve sekme dahil), biçim (bidi override, sıfır genişlikli, BOM), surrogate ve satır/paragraf ayırıcı karakterler: `"IOC contains control or invisible formatting characters."` — değer yansıtılmaz |
| 1 | IPv4 | `ipaddress.IPv4Address` |
| 2 | IPv6 | `ipaddress.IPv6Address` |
| 3–5 | MD5 / SHA1 / SHA256 | 32 / 40 / 64 onaltılık karakter |
| 6 | URL | `http://` veya `https://` ile başlar (büyük/küçük harf duyarsız) |
| 7 | E-posta | `yerel@alan.tld`, en az 2 harfli alfabetik TLD |
| 8 | Alan adı | en fazla 253 karakter, 1–63 harf/rakam/tireden oluşan etiketler, alfabetik TLD |
| — | bilinmeyen | `"'<değer>' does not match any supported IOC type …"` |

`IOCValidator.identify(raw)` yalnızca tespit edilen `IOCType` değerini
döndürür (eşleşme yoksa `UNKNOWN`).

Bilinmesi gereken davranışlar (koda karşı doğrulandı):

- Değer normalleştirilmez: harf büyüklüğü korunur (`Malicious.Example.COM`
  yazıldığı gibi kalır); bu yüzden büyük/küçük harf varyantları ayrı önbellek
  kayıtlarıdır.
- Özel, loopback ve dokümantasyon adresleri geçerli IP'dir ve diğerleri gibi
  sağlayıcılara gönderilir.
- `ftp://` ve diğer şemalar reddedilir; noktalı alanı olmayan bir e-posta
  adresi (`user@localhost`) de reddedilir.
- URL kuralı şemayı denetler; URL'nin geri kalanındaki olağan Unicode
  (`https://example.com/ürün`) geçerli kalır, kontrol, bidi ve sıfır
  genişlikli karakterler ise yukarıdaki denetimle reddedilir. Sağlayıcı ve AI
  metni çıktıda yine etkisizleştirilir (bkz.
  [Güvenlik Değerlendirmeleri](../security/considerations.md)).

---

## 4. Örnekler

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

CLI: `python -m ioc_enricher --ioc not-an-ioc`, `❌ Validation error: …`
yazdırır ve 1 koduyla çıkar.

---

## 5. Güvenlik notları

| Risk | Kontrol | Sınır |
|---|---|---|
| Aşırı uzun girdi | 2048 karakter sınırı (alan adları 253) | — |
| IOC üzerinden enjeksiyon | Türe göre doğrulama; sağlayıcılar değeri sabit bir HTTPS URL'si veya sorgusu içinde alır; URL aramaları kodlanır (VirusTotal URL kimliği, OTX percent-encoding); ZeroBounce e-postayı POST form gövdesinde alır | URL'nin yolu ve sorgusu incelenmez |
| Terminal / görüntü hileleri | Kontrol, bidi veya sıfır genişlikli karakter içeren IOC'ler reddedilir; sağlayıcı ve AI metni CLI ve arayüzde kaçışlanır | — |
| Yanlışlıkla ifşa | — | İç IOC'ler dahil her geçerli IOC, yapılandırılmış her sağlayıcıya gönderilir |

---

## 6. İlgili Belgeler

- [Zenginleştirme Motoru](enrichment-engine.md)
- [CLI Kullanımı](../cli/usage.md)
- [Güvenlik Değerlendirmeleri](../security/considerations.md)
- [Test: test_validator](../tests/test_validator.md)
