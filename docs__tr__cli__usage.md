# CLI Kullanımı

## 1. Genel Bakış

Komut satırı arayüzü (`cli/main.py`, `argparse`) tek bir IOC'yi veya bir IOC
dosyasını zenginleştirir, raporları yazdırır veya kaydeder ve önbelleği
yönetir:

```bash
python -m ioc_enricher [SEÇENEKLER]
```

Aşağıdaki örnekler dokümantasyon adresleri (RFC 5737) ve sahte değerler
kullanır.

---

## 2. Güvenlik notları

- Açık bir IOC argümanı olmadan hiçbir sağlayıcı sorgulanmaz.
- API anahtarları yalnızca ortamdan veya **geçerli dizindeki** `.env`
  dosyasından gelir (`IOC_ENRICHER_DOTENV=<yol>` başka bir dosya seçer,
  `IOC_ENRICHER_DOTENV=0` kapatır); hiçbir zaman CLI argümanı veya istem
  değildir ve ortamda zaten olan değişkenler önceliklidir.
- Güvenilmeyen metin — sağlayıcı alanları, AI çıktısı, hata mesajları,
  dosyadan okunan IOC'ler — terminal kontrol karakterleri görünür hâle
  getirilerek yazdırılır: ESC (ekranı temizleyebilen veya pencere başlığını
  değiştirebilen CSI/OSC dizileri), BEL, CR, 8 bit C1 kontrolleri, bidi
  override'ları ve sıfır genişlikli karakterler `\x1b` veya `\u202e` gibi
  kaçış dizileri olarak görünür. Normal metin değişmez. Bu kural terminal,
  tablo ve Markdown biçimlerinde geçerlidir; JSON biçimleri bu karakterleri
  `\uXXXX` olarak kaçırır, böylece çözülen değerler aynı kalır.
- Kendisi kontrol, bidi veya sıfır genişlikli karakter içeren bir IOC,
  herhangi bir sağlayıcı çağrısından önce reddedilir (`❌ Validation error:
  IOC contains control or invisible formatting characters.`); mesaj değeri
  yansıtmaz.
- Log satırları stderr'e gider ve IOC'leri değeriyle değil, anahtarlı bir
  parmak iziyle anar (`ipv4#051be4c68a3a`).
- Kaydedilen rapor adlarında IOC hiçbir zaman yer almaz (bölüm 7).

---

## 3. Kurulum

```bash
python -m pip install -r requirements.txt   # hash'li lock (requirements/test.txt)
python -m pip install --no-deps -e .         # paketin kendisi
cp .env.example .env                         # ardından sağlayıcı anahtarlarını ekleyin
python -m ioc_enricher --status
```

Python 3.11 veya üzeri gerekir (`pyproject.toml`); CI ve backend imajı 3.12
kullanır.

---

## 4. Komut başvurusu

### IOC girişi (birbirini dışlar)

| Bayrak | Açıklama |
|---|---|
| `--ip ADRES` | IPv4 veya IPv6 adresi |
| `--domain ALAN` | Alan adı |
| `--hash HASH` | MD5, SHA1 veya SHA256 |
| `--url URL` | URL (`http://` veya `https://`) |
| `--email EPOSTA` | E-posta adresi |
| `--ioc DEĞER` | Herhangi bir IOC; tür otomatik algılanır |
| `--file DOSYA` | Satır başına bir IOC (toplu mod) |

### Çıktı

| Bayrak | Değerler | Varsayılan |
|---|---|---|
| `--output` | `terminal`, `json`, `markdown`, `table`, `ndjson` | `terminal` |
| `--save` | `json`, `markdown`, `table`, `ndjson` | yok |

`--output` tek IOC çalıştırmalarında geçerlidir; toplu mod IOC başına bir
özet satırı yazdırır.

### Önbellek ve yardımcılar

| Bayrak | Açıklama |
|---|---|
| `--no-cache` | Bu çalıştırmada önbelleği atla |
| `--clear-cache` | Önbellek kayıtlarını sil ve çık |
| `--cache-stats` | Önbellek istatistiklerini yazdır ve çık |
| `--status` | Sağlayıcı ve AI anahtar durumunu yazdır ve çık |
| `--no-banner` | Banner'ı gösterme |
| `--version` | Sürümü yazdır ve çık |

---

## 5. Örnekler

```bash
python -m ioc_enricher --ip 203.0.113.7
python -m ioc_enricher --domain malicious.example.com
python -m ioc_enricher --hash 44d88612fea8a8f36de82e1278abb02f
python -m ioc_enricher --url "https://malicious.example.com/payload.exe"
python -m ioc_enricher --email phisher@malicious.example.com
python -m ioc_enricher --ioc 203.0.113.7            # tür otomatik algılanır

# Defanged girdi, harf büyüklüğü fark etmeksizin otomatik düzeltilir
python -m ioc_enricher --url "hxxps://malicious[.]example[.]com/path"
python -m ioc_enricher --url "HXXPS://malicious[DOT]example[DOT]com/path"
python -m ioc_enricher --ioc "203[.]0[.]113[.]7"

# Toplu
python -m ioc_enricher --file iocs.txt --no-cache
python -m ioc_enricher --file iocs.txt --save json  # IOC başına bir rapor
```

`iocs.txt`: satır başına bir IOC; boş satırlar ve `#` ile başlayan satırlar
atlanır.

---

## 6. Çıktı biçimleri

| `--output` | İçerik |
|---|---|
| `terminal` | Rapor: IOC, tür, zaman, risk skoru ve seviyesi, tespit güveni, kanıt satırı, gerekçeler, "why" satırları (model yazdıysa `(AI narrative)`), insan incelemesi uyarısı, sağlayıcı sonuçları, MITRE ATT&CK, AI özeti ve audit satırı. Yalnızca etkileşimli terminalde renklidir; boruya veya dosyaya yönlendirildiğinde ve `NO_COLOR` ayarlıyken düz metindir. |
| `table` | Düz metin tablo, ANSI kodu yok; kanıt satırlarını içerir. |
| `markdown` | Markdown rapor (sağlayıcı metninden ters tırnak ve `<>` çıkarılır); bir kanıt satırı ve `insufficient_data` ya da `partial` kanıt için bir not içerir. |
| `json` | Girintili `result.to_dict()`. |
| `ndjson` | Aynı kayıt tek satırda. |

Her biçim skorun ne kadar kanıta dayandığını söyler; böylece hiçbir
sağlayıcının kullanılabilir veri döndürmediği bir çalıştırma asla temiz bir
`0/100 LOW` gibi okunmaz:

| Biçim | Gösterilen |
|---|---|
| `terminal` | `Evidence: insufficient data — … this score is not a clean verdict.`, `Evidence: partial — 1/2 providers returned data; unavailable: …` veya `Evidence: complete — …`; kanıt yoksa seviye işaretinin yerine ❔ |
| `table` | `Evidence Status`, `Providers With Data`, `Unavailable Providers` satırları; `No usable data; not a clean verdict` notu |
| `markdown` | `Evidence Status` metrik satırı; "Insufficient data" / "Partial coverage" notu |
| `json`, `ndjson` | `evidence_status`, `provider_coverage`, `unavailable_providers` |
| `--file` toplu satırı | `(insufficient data — not a clean verdict)` veya `(partial: N provider(s) unavailable)`; ✅ yerine ❔ |

JSON kaydının üst düzey anahtarları şunlardır: `metadata` (`ioc`,
`ioc_type`, `timestamp`, `execution_time_s`, `from_cache`),
`risk_assessment` (`score`, `level`, `detection_confidence`, `reasons`,
`evidence_status`, `provider_coverage`, `unavailable_providers`, …),
`threat_intelligence` (sağlayıcı başına sonuçlar), `mitre_attack` ve
`ai_analysis`.

**stdout yalnızca rapordan oluşmaz:** tek IOC çalıştırması rapordan önce
`🔍 Analysing: <ioc>`, sonra `⏱️  Completed in …s` (önbellek isabetinde ayrıca
`💾 Result served from cache.`) yazdırır. Boruya vermeden önce JSON'u ayıklayın:

```bash
python -m ioc_enricher --no-banner --ioc 203.0.113.7 --output ndjson | grep '^{' | jq '.risk_assessment.level'
python -m ioc_enricher --no-banner --ioc 203.0.113.7 --output json | sed -n '/^{/,/^}/p' | jq '.risk_assessment.reasons[]'
```

---

## 7. Rapor kaydetme

`--save BİÇİM`, zenginleştirilen her IOC için `Config.REPORTS_DIR` dizinine
(kaynak kodda `ioc_enricher/reports/`) bir dosya yazar ve nereye yazdığını
yazdırır:

```
💾 Report saved: <rapor dizini>/ioc_ipv4_20261028T101500Z_3f9c2a1b.json
```

| Biçim | Uzantı |
|---|---|
| `json` | `.json` |
| `markdown` | `.md` |
| `table` | `.txt` |
| `ndjson` | `.ndjson` |

- Ad: `ioc_<tür>_<UTC zaman>_<8 rastgele hex>.<uzantı>` — IOC değeri asla
  adın parçası değildir (adlar listelemelerde, kabuk geçmişinde,
  yedeklerde görünür).
- Var olan bir dosyanın üzerine asla yazılmaz: çakışmada yeni bir rastgele
  sonek üretilir.
- Dosyalar POSIX'te yalnızca sahibine açık oluşturulur.
- CLI raporları otomatik olarak budanmaz (`REPORT_RETENTION_DAYS` yalnızca
  web raporlarına uygulanır); artık gerekmediğinde silin.

---

## 8. Önbellek ve durum çıktısı

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

## 9. Çıkış kodları

| Kod | Ne zaman |
|---|---|
| `0` | Tek IOC zenginleştirildi (herhangi bir risk seviyesi); toplu iş bitti (bazı IOC'ler başarısız olsa bile — `❌` satırlarına bakın); `--status`, `--cache-stats`, `--clear-cache`, `--version` |
| `1` | IOC verilmedi, doğrulama hatası, zenginleştirme hatası, başlatma hatası, `--file` yok veya IOC içermiyor |

---

## 10. İlgili Belgeler

- [Önbellek Sistemi ve Rapor Saklama](../features/cache-system.md)
- [Zenginleştirme Motoru](../features/enrichment-engine.md)
- [Risk Puanlama](../scoring/risk-scoring.md)
