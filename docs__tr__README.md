# IOC Enricher — Belgeleme

> Uzlaşma Göstergeleri için çok kaynaklı tehdit istihbaratı zenginleştirme

---

## Hızlı Gezinti

### Mimari
- [Sistem Genel Bakış](architecture/overview.md) — boru hattı aşamaları, bileşen haritası, eş zamanlılık modeli

### Özellikler
- [Zenginleştirme Motoru](features/enrichment-engine.md) — ana boru hattı yöneticisi
- [IOC Doğrulama](features/ioc-validation.md) — tür tespiti, defanging, format doğrulama
- [Önbellek Sistemi ve Rapor Saklama](features/cache-system.md) — dosya önbelleği, boyut sınırı, rapor saklama
- [Rate Limiter, Zaman Aşımları ve Circuit Breaker](features/rate-limiter.md) — sınırlı bekleme, HTTP 429, süre bütçeleri, yeniden denemeler
- [MITRE ATT&CK Eşleme](features/mitre-mapping.md) — sezgisel teknik eşleme
- [AI Analizi](features/ai-analysis.md) — isteğe bağlı Groq anlatı katmanı, gönderilen veri, yanıt doğrulama

### Risk Puanlama
- [Risk Puanlama Modeli](scoring/risk-scoring.md) — 0–100 deterministik puanlama, sağlayıcı ağırlıkları, eşikler

### Sağlayıcılar
- [Sağlayıcı Genel Bakış](providers/overview.md) — yetenek matrisi, BaseProvider mimarisi
- [VirusTotal](providers/virustotal.md) — çok motorlu kötü amaçlı yazılım taraması (maks. 35 puan)
- [AbuseIPDB](providers/abuseipdb.md) — IP kötüye kullanım güven puanlama (maks. 25 puan)
- [Shodan](providers/shodan.md) — cihaz parmak izi + CVE'ler (maks. 10 puan)
- [AlienVault OTX](providers/otx.md) — tehdit istihbaratı darbeleri (maks. 15 puan)
- [GreyNoise](providers/greynoise.md) — internet gürültüsü sınıflandırması (maks. 10 puan)
- [ZeroBounce](providers/zerobounce.md) — e-posta doğrulama puanlaması (maks. 5 puan)

### CLI
- [CLI Kullanımı](cli/usage.md) — komutlar, bayraklar, çıktı formatları, toplu işleme

### Güvenlik
- [Güvenlik Değerlendirmeleri](security/considerations.md) — tehdit modeli, sertleştirme kontrol listesi

### Testler
- [test_validator](tests/test_validator.md) — IOC tür tespiti ve doğrulama testleri
- [test_scoring](tests/test_scoring.md) — risk puanlama doğruluk testleri
- [test_cache](tests/test_cache.md) — önbellek TTL ve davranış testleri
- [test_providers](tests/test_providers.md) — sağlayıcı yanıt ayrıştırma testleri
- [test_aggregator_mitre](tests/test_aggregator_mitre.md) — toplama ve MITRE eşleme testleri

### Geliştirme
- [Katkı Rehberi](development/contributing.md) — kurulum, sağlayıcı ekleme, kod stili

---

## Risk Puanı Başvurusu

| Puan | Seviye | Eylem |
|---|---|---|
| 0–20 | `LOW` (düşük) | İzle veya yoksay |
| 21–50 | `MEDIUM` (orta) | Soruştur |
| 51–80 | `HIGH` (yüksek) | Önceliklendir ve tırmandır |
| 81–100 | `CRITICAL` (kritik) | Anında müdahale |

Varsayılan eşiklerdir; `SCORE_LOW_MAX`, `SCORE_MEDIUM_MAX` ve
`SCORE_HIGH_MAX` bunları değiştirir. Bir seviyeyi `evidence_status` ile
birlikte okuyun: `partial` veya `insufficient_data` kanıtlı bir `LOW`,
"yoksayılabilir" değil, "yeterli kanıt yok" demektir.

---

## Sağlayıcı Ağırlık Başvurusu

| Sağlayıcı | Maks. Puan | Birincil Sinyal |
|---|---|---|
| VirusTotal | 35 | Motor tespit oranı |
| AbuseIPDB | 25 | Kötüye kullanım güven puanı |
| OTX | 15 | Tehdit darbesi sayısı |
| Shodan | 10 | CVE'ler + yüksek riskli portlar |
| GreyNoise | 10 | Zararlı sınıflandırma |
| ZeroBounce | 5 | Toxic / spam tuzağı / kötüye kullanım sinyalleri |

---

*İngilizce belgeleme için bkz. [../en/README.md](../en/README.md)*
