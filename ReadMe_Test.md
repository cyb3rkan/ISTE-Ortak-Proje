# 🧪 Test Rehberi

## ⚡ Hızlı Test

Depo kökünden, kurulumdan sonra:

```bash
python -m pip install -r requirements.txt   # hash'li test lock'u (requirements/test.txt)
python -m pip install --no-deps -e .
python -m pytest tests ioc_enricher/tests -q
```

- Hiçbir test sağlayıcı veya AI anahtarı gerektirmez; sağlayıcı ve Groq
  çağrıları mock'lanır.
- `tests/conftest.py` ve `ioc_enricher/tests/__init__.py`,
  `IOC_ENRICHER_DOTENV=0` ve boş `LOG_FILE` ayarlar: geliştiricinin gerçek
  `.env` dosyası testlere asla yüklenmez ve test kayıtları `logs/` altına
  yazılmaz.
- Paket kurulmadan da depo kökünden `pytest` ve `python -m pytest`, `tests/`
  ağacını içeren çalıştırmalarda çalışır; yalnızca `ioc_enricher/tests` için
  düz `pytest` kullanın veya `PYTHONPATH=ioc_enricher` ayarlayın.
- Windows'ta POSIX dosya izni testleri (2 adet) atlanır.

---

## 🏁 CI'nin çalıştırdığı komut

```bash
python -m pytest ioc_enricher/tests tests/adapter tests/cli tests/api tests/security \
  --cov=ioc_enricher --cov-report=term-missing --cov-fail-under=80 -q
```

Herhangi bir test başarısız olursa veya coverage %80'in altına düşerse CI
başarısız olur; "kabul edilebilir başarı oranı" diye bir eşik yoktur. Bu belge
belirli bir çalıştırmanın sonucunu kaydetmez.

---

## 🎯 Test Kategorileri

| Dizin | Kapsam |
|-------|--------|
| `ioc_enricher/tests/` | IOC doğrulama ve refang, puanlama ve kanıt durumu, EICAR, önbellek yaşam döngüsü, sağlayıcı sözleşmeleri ve URL kodlama, hız sınırı / süre bütçesi / circuit breaker (`test_provider_limits.py`), AI yanıt doğrulama, güvenilmeyen girdi, Türkçe çıktı, `.env` yükleme, log hijyeni, aggregator ve MITRE |
| `tests/adapter/` | Web servis katmanı: DTO eşleme, API sözleşmesi (`data_summary`, hata maskeleme, AI `source`), batch süre bütçesi, rapor deposu ve saklama |
| `tests/api/` | FastAPI rotaları: health, enrich, batch, providers, cache, reports, hata gövdeleri |
| `tests/cli/` | CLI geriye uyumluluk ve terminal çıktısının kontrol/bidi karakterlerini etkisizleştirmesi |
| `tests/security/` | API anahtarı ve JWT kimlik doğrulama, güvenli varsayılanlar, CSRF, CORS, güvenlik başlıkları, istek boyutu, rate limit, Redis, refresh rotasyonu, docs erişimi, hata sızıntısı, örnek yapılandırma, AI sır maskeleme, frontend konteyneri, tedarik zinciri |
| `tests/integration/` | Playwright entegrasyon testleri için sahte enricher'lı gerçek FastAPI sunucusu (`e2e_server.py`) |
| `frontend/tests/` | Vitest birim testleri (API istemcisi, auth akışı, güvenli render, sonuç anlamı, …) |
| `frontend/e2e/` | Playwright E2E (mock'lanmış API) |

---

## 🖥️ Arayüz testleri

```bash
cd frontend
npm ci
npm run test             # Vitest
npm run build            # tsc -b + üretim derlemesi
npm run e2e:install      # bir kez: Playwright Chromium
npm run e2e              # Playwright, mock'lanmış API
npm run e2e:integration  # Playwright, sahte enricher'lı gerçek FastAPI uygulaması
```

---

## 🔍 Manuel Test Komutları

Anahtar yapılandırılmamışsa aşağıdaki komutlar ağa çıkmaz; anahtar varsa
IOC'ler sağlayıcılara gönderilir. Örnekler yalnızca dokümantasyon değerleri
kullanır.

### Provider Durumu
```bash
python -m ioc_enricher --status
```

### Tek IOC
```bash
python -m ioc_enricher --ip 203.0.113.7
python -m ioc_enricher --domain malicious.example.com
python -m ioc_enricher --hash 44d88612fea8a8f36de82e1278abb02f
```

### Farklı Formatlar
```bash
# JSON
python -m ioc_enricher --ip 198.51.100.23 --output json

# Markdown
python -m ioc_enricher --domain malicious.example.com --output markdown

# Dosyaya kaydet
python -m ioc_enricher --ip 203.0.113.7 --save json
```

### Geçersiz girdi
```bash
python -m ioc_enricher --ioc not-an-ioc   # "❌ Validation error: …", çıkış kodu 1
```

### Batch Processing
```bash
python -m ioc_enricher --file example_iocs.txt
```

---

## ✅ Test Tamamlandıktan Sonra

1. ✅ Tüm testlerin geçtiğini ve atlananların yalnızca beklenen POSIX izin
   testleri olduğunu kontrol et
2. ✅ Kendi IOC'lerinle denemeden önce bunların üçüncü taraf sağlayıcılara
   (ve AI açıksa Groq'a) gönderileceğini hesaba kat
3. ✅ Farklı formatları test et
4. ✅ Raporları ve önbelleği paylaşmadan önce temizle

---

**Mutlu testler! 🧪**
