# 🚀 Hızlı Başlangıç Kılavuzu

## ⏱️ Kısa Yoldan Başla

Tüm komutlar depo kökünden çalıştırılır.

### Adım 1: Bağımlılıkları Yükle

```bash
# Virtual environment oluştur (opsiyonel ama önerilen)
python -m venv venv

# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate

# Hash'li bağımlılıkları ve paketi yükle (Python 3.11+)
python -m pip install -r requirements.txt
python -m pip install --no-deps -e .
```

### Adım 2: API Anahtarlarını Ekle

`.env` dosyasını şablondan oluştur ve elindeki anahtarları ekle:

```bash
cp .env.example .env
```

```bash
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
OTX_API_KEY=
GREYNOISE_API_KEY=
ZEROBOUNCE_API_KEY=
GROQ_API_KEY=          # isteğe bağlı AI anlatısı; IOC verisini Groq'a gönderir
```

**Not:** Depo hiçbir API anahtarı içermez; `.env.example` tüm sır alanlarını
boş bırakır. `.env` dosyasını asla commit'leme. Hiç anahtar olmadan da araç
çalışır, ancak her sonuç `insufficient_data` (kanıt yok) olur.

### Adım 3: Test Et

```bash
# Provider durumunu kontrol et
python -m ioc_enricher --status

# İlk IP analizini yap (dokümantasyon adresi, RFC 5737)
python -m ioc_enricher --ip 203.0.113.7

# Domain analizi
python -m ioc_enricher --domain malicious.example.com

# Batch test
python -m ioc_enricher --file example_iocs.txt
```

Anahtar eklediysen bu komutlar IOC'leri yapılandırılmış sağlayıcılara
gönderir.

## 📋 Temel Komutlar

```bash
# Tek IOC analizi
python -m ioc_enricher --ip 198.51.100.23
python -m ioc_enricher --domain malicious.example.com
python -m ioc_enricher --hash 44d88612fea8a8f36de82e1278abb02f
python -m ioc_enricher --url http://malicious.example.com/payload.exe

# Otomatik tip tespiti
python -m ioc_enricher --ioc 203.0.113.7

# JSON çıktı
python -m ioc_enricher --ip 203.0.113.7 --output json

# Rapor kaydet (json | markdown | table | ndjson)
python -m ioc_enricher --ip 203.0.113.7 --save markdown

# Dosyadan toplu analiz
python -m ioc_enricher --file example_iocs.txt
```

## 🎯 İlk Hedefler

1. ✅ Projeyi çalıştır (`--status`)
2. ✅ Bir dokümantasyon IP'sini (203.0.113.7) analiz et
3. ✅ EICAR test hash'ini analiz et
4. ✅ Batch analiz yap
5. ✅ JSON rapor oluştur

## 📚 Sonraki Adımlar

1. [Ana belge (TR)](ReadMe_Main.md) ve [README.md](../README.md) oku
2. [CLI Kullanımı](tr/cli/usage.md) belgesindeki biçimlere ve çıkış kodlarına bak
3. Raporları incele — CLI raporları `ioc_enricher/reports/` altında kalır ve
   otomatik silinmez
4. Web arayüzü ve Docker için [README.md](../README.md) ve
   [docker/README.md](../docker/README.md) belgelerine geç

## 💡 İpuçları

- `--help` parametresi ile tüm seçenekleri gör
- `--no-banner` ile banner'ı gizle
- `--output json` / `--output ndjson` ile programatik kullanım; stdout'ta
  rapordan önce ve sonra durum satırları da vardır (bkz. CLI belgesi)
- Terminal çıktısındaki `Evidence:` satırı skorun ne kadar kanıta
  dayandığını söyler; `insufficient data` veya `partial` görürsen `LOW`
  sonucunu temiz sayma (JSON'da `evidence_status`)
- `example_iocs.txt` yalnızca dokümantasyon değerleri içerir; kendi
  IOC'lerinle test ederken bunların üçüncü taraflara gönderildiğini unutma

## 🎉 Hazırsın!

Artık IOC Enricher Agent'ı kullanmaya hazırsın. Mutlu analizler! 🚀
