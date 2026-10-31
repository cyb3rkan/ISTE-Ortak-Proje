# 🔍 IOC Enricher Agent

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-Optional_narrative-blueviolet?style=for-the-badge)

**Tehdit istihbaratı toplama ve deterministik risk puanlama — isteğe bağlı AI anlatısıyla**

Birden fazla tehdit istihbaratı sağlayıcısından gelen veriyi, Indicator of
Compromise (IOC) için deterministik ve kanıt durumunu belirten bir risk
değerlendirmesinde birleştiren bir siber güvenlik aracı. İsteğe bağlı AI
katmanı (Groq) bunun üzerine bir anlatı ekler; skoru veya kanıtı asla
değiştirmez.

İngilizce ana belge: [README.md](../README.md). Ayrıntılı başvuru belgeleri:
[docs/tr/README.md](tr/README.md).

---

## 🎯 Problem ve Çözüm

### ❌ Geleneksel Yöntem
Bir SOC analisti şüpheli bir IP adresi gördüğünde birkaç tehdit istihbaratı
platformunu elle kontrol eder ve yanıtları kendisi birleştirir.

### ✅ Bu Araç ile
Tek bir komut (veya API çağrısı) yapılandırılmış sağlayıcıları eşzamanlı
sorgular, kanıtı deterministik olarak puanlar ve hangi sağlayıcıların yanıt
vermediğini de söyleyen tek bir rapor üretir.

Depoda IOC başına süre ölçümü yoktur. Bir IOC'nin sağlayıcı aşaması
`IOC_DEADLINE_SECONDS` (varsayılan 60 sn) ile sınırlıdır; gerçek süre
sağlayıcıların yanıt sürelerine ve hız sınırlarına bağlıdır (örneğin
VirusTotal genel API'si dakikada 4 isteğe izin verir).

---

## ✨ Özellikler

### 🔎 Çok kaynaklı istihbarat

| Sağlayıcı | Kullanım |
|-----------|----------|
| **VirusTotal** | IP, alan adı, URL ve dosya hash'i tespitleri |
| **AbuseIPDB** | IP kötüye kullanım raporları ve güven skoru, Tor bayrağı |
| **Shodan** | IP ve alan adları için açık portlar, servisler ve CVE kimlikleri |
| **AlienVault OTX** | IP, alan adı, URL ve hash'ler için tehdit pulse'ları |
| **GreyNoise** | IP'lerin internet gürültüsü / zararlı sınıflandırması |
| **ZeroBounce** | E-posta doğrulama: toxic, spam tuzağı, kötüye kullanım ve tek kullanımlık adres tespiti, alan adı yaşı |

### 🤖 AI anlatısı (isteğe bağlı)
- **Groq** tabanlı tehdit analizi anlatısı (desteklenen tek AI altyapısı)
- AI katmanı **yalnızca ekleme yapar** — deterministik skorun üzerine anlatı
  üretir ve **risk skorunu asla değiştirmez**
- Deterministik, AI'dan bağımsız risk skoru (0-100)
- Seviye (LOW/MEDIUM/HIGH/CRITICAL) ve kanıt durumu
  (`complete` / `partial` / `insufficient_data`)
- Türkçe anlatılar (teknik terimler İngilizce kalır); deterministik yedek
  analiz de Türkçedir
- Önceliklendirilmiş öneriler; her yanıt şemaya göre doğrulanır ve en küçük
  uyumsuzlukta bütünüyle reddedilir

### 📊 Raporlama
- Renkli terminal çıktısı ve düz metin tablo
- JSON ve NDJSON
- Markdown raporlar
- Web arayüzü (React, bkz. [README.md](../README.md))

### ⚡ Performans ve dayanıklılık
- Eşzamanlı sağlayıcı çağrıları (sınırlı worker havuzu, `MAX_CONCURRENT_REQUESTS`)
- Toplu işleme (IOC'ler art arda işlenir)
- Sınırlı beklemeli sağlayıcı hız sınırları, yeniden denemeler, circuit
  breaker ve IOC başına süre bütçesi — başarısız bir sağlayıcı raporlanır,
  zenginleştirmeyi durdurmaz
- TTL ve boyut sınırı olan dosya önbelleği

---

## 📦 Kurulum

### Gereksinimler

- Python 3.11 veya üzeri (CI ve backend imajı 3.12 kullanır)
- pip paket yöneticisi
- Arayüz için Node.js 24 (CI Node 24 kullanır)
- Sağlayıcı API anahtarları — isteğe bağlı; hiç anahtar yoksa her sonuç
  `insufficient_data` olur

### Hızlı Başlangıç

```bash
# 1. Projeyi indir
git clone https://github.com/cyb3rkan/ioc-enricher-agent.git

# 2. Proje dizinine gir
cd ioc-enricher-agent

# 3. Virtual environment oluştur (önerilen)
python -m venv venv

# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate

# 4. Hash'li bağımlılıkları ve paketi yükle
python -m pip install -r requirements.txt
python -m pip install --no-deps -e .

# 5. .env dosyasını oluştur ve API anahtarlarını ekle
cp .env.example .env

# 6. Test et
python -m ioc_enricher --status
```

---

## 🔑 API Anahtarları

| Servis | Değişken | Kullanım | Kayıt Linki |
|--------|----------|----------|-------------|
| VirusTotal | `VIRUSTOTAL_API_KEY` | IP, alan adı, URL, hash | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP | [abuseipdb.com](https://www.abuseipdb.com/register) |
| Shodan | `SHODAN_API_KEY` | IP, alan adı | [shodan.io](https://account.shodan.io/register) |
| AlienVault OTX | `OTX_API_KEY` | IP, alan adı, URL, hash | [otx.alienvault.com](https://otx.alienvault.com/api) |
| GreyNoise | `GREYNOISE_API_KEY` | IP | [greynoise.io](https://www.greynoise.io/) |
| ZeroBounce | `ZEROBOUNCE_API_KEY` | E-posta | [zerobounce.net](https://www.zerobounce.net/docs/email-validation-api-quickstart/v2-getting-started) |
| Groq | `GROQ_API_KEY` | İsteğe bağlı AI anlatısı | [console.groq.com](https://console.groq.com/keys) |

Her anahtar isteğe bağlıdır: anahtarı olmayan sağlayıcı sorgulanmaz. Ücretsiz
planlar, kotalar ve kullanım koşulları her sağlayıcı tarafından belirlenir ve
burada modellenmez — sağlayıcının sitesinden kontrol edin; istemci tarafı hız
varsayılanları [Rate Limiter](tr/features/rate-limiter.md) belgesindedir.

### .env Dosyası Yapılandırması

`.env` dosyasını asla commit'lemeyin.

```bash
# Tehdit istihbaratı sağlayıcıları (bir sağlayıcıyı kapatmak için boş bırakın)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
OTX_API_KEY=
GREYNOISE_API_KEY=
ZEROBOUNCE_API_KEY=

# AI katmanı — yalnızca Groq (groq | disabled); anahtar varsa IOC verisini Groq'a gönderir
AI_PROVIDER=groq
GROQ_API_KEY=
```

Groq'a hangi verinin gönderildiği [AI Analizi](tr/features/ai-analysis.md)
belgesinde listelenir. `AI_PROVIDER=disabled` anahtardan bağımsız olarak AI
katmanını kapatır.

---

## 🚀 Kullanım

### Temel Kullanım

```bash
# IP adresi analizi
python -m ioc_enricher --ip 203.0.113.7

# Domain analizi
python -m ioc_enricher --domain malicious.example.com

# Hash analizi (EICAR test dosyası MD5)
python -m ioc_enricher --hash 44d88612fea8a8f36de82e1278abb02f

# URL analizi
python -m ioc_enricher --url http://malicious.example.com/malware.exe

# Otomatik tip tespiti
python -m ioc_enricher --ioc 198.51.100.23
```

### İleri Seviye Kullanım

```bash
# JSON formatında çıktı
python -m ioc_enricher --ip 203.0.113.7 --output json

# Markdown rapor kaydet
python -m ioc_enricher --domain malicious.example.com --save markdown

# Dosyadan toplu analiz
python -m ioc_enricher --file example_iocs.txt

# Provider durumunu kontrol et
python -m ioc_enricher --status
```

Raporlar `ioc_enricher/reports/` altına `ioc_<tür>_<UTC zaman>_<rastgele>.<uzantı>`
adıyla yazılır (üzerine yazılmaz, otomatik budanmaz). Tüm bayraklar, biçimler
ve çıkış kodları: [CLI Kullanımı](tr/cli/usage.md). Eski `python main.py`
çağrısı `legacy/` altındadır ve desteklenmez.

### Örnek Çıktı

Hiç sağlayıcı anahtarı olmadan gerçek bir CLI çalıştırması (çıktı
yönlendirildiği için renksiz):

```
🔍 Analysing: 203.0.113.7


══════════════════════════════════════════════════════════════════════
   🔍 IOC ENRICHMENT REPORT
══════════════════════════════════════════════════════════════════════

IOC   :  203.0.113.7
Type  :  IPV4
Time  :  2026-10-29 03:32:47 UTC

──────────────────────────────────────────────────────────────────────
🎯  RISK SCORE:  0/100  ❔  LOW
    Detection Confidence: 0%
    Evidence: insufficient data — no provider was queried; this score is not a clean verdict.
──────────────────────────────────────────────────────────────────────

📊 PROVIDER RESULTS
──────────────────────────────────────────────────────────────────────

══════════════════════════════════════════════════════════════════════

⏱️  Completed in 0.00s
```

Sağlayıcılar yapılandırıldığında rapora skor gerekçeleri, "why malicious /
why benign" satırları, sağlayıcı sonuçları, MITRE ATT&CK teknikleri ve — AI
katmanı açıksa — audit satırıyla AI özeti eklenir. `Evidence:` satırı ve ❔
işareti, yukarıdaki `LOW` sonucunun "temiz" değil "kanıt yok" anlamına
geldiğini söyler (`--output json` çıktısında `evidence_status:
insufficient_data`); bazı sağlayıcılara ulaşılamazsa satır `partial — …`
olur.

---

## 📁 Proje Yapısı

```
ioc-enricher-agent/
├── ioc_enricher/
│   ├── ioc_enricher/          # paket (core, providers, models, mitre,
│   │                          # reports, utils, web, cli, enricher.py)
│   ├── tests/                 # paket birim testleri
│   └── README.md              # paket README'si
├── tests/                     # adapter, api, cli, security, integration testleri
├── frontend/                  # React + Vite + TypeScript arayüz
├── docker/                    # Dockerfile'lar, docker-compose.yml, nginx.conf
├── docs/                      # belgeler (en/, tr/ ve rehberler)
├── legacy/                    # kullanımdan kalkmış prototip (kullanmayın)
├── requirements/              # hash'li lock dosyaları (runtime, test, build, tools)
├── example_iocs.txt           # örnek IOC listesi (dokümantasyon değerleri)
├── requirements.txt           # = requirements/test.txt
├── pyproject.toml
├── .env.example
├── SECURITY.md
├── LICENSE
└── README.md
```

Çalışma zamanı dizinleri (`data/`, `logs/`, `reports/`, `ioc_enricher/` altında
da) gerektiğinde oluşturulur ve git tarafından yok sayılır; soruşturma verisi
içerirler.

---

## 🧪 Test

```bash
# Tüm backend testleri (kurulumdan sonra)
python -m pytest tests ioc_enricher/tests -q

# CI'nin çalıştırdığı komut (coverage eşiği %80)
python -m pytest ioc_enricher/tests tests/adapter tests/cli tests/api tests/security \
  --cov=ioc_enricher --cov-report=term-missing --cov-fail-under=80 -q
```

Paket kurulmadan da depo kökünden `pytest` ve `python -m pytest`, `tests/`
ağacını içeren çalıştırmalarda (yukarıdaki komutlar) çalışır; yalnızca
`ioc_enricher/tests` için düz `pytest` kullanın veya `PYTHONPATH=ioc_enricher`
ayarlayın. Hiçbir test sağlayıcı veya AI anahtarı gerektirmez. Arayüz testleri
ve ayrıntılar: [README.md](../README.md) ve [Test Rehberi](ReadMe_Test.md).

---

## 🔒 Güvenlik

- 🔐 API anahtarlarınızı kimseyle paylaşmayın; açığa çıkan bir anahtarı
  sağlayıcıda iptal edip yenileyin.
- 💾 Önbellek, rapor ve log dosyaları soruşturma verisi içerir; dizinleri
  özel tutun. CLI raporları otomatik silinmez.
- 🌐 IOC'ler yapılandırılmış her sağlayıcıya ve AI katmanı açıksa Groq'a
  gönderilir; bu proje üçüncü tarafların veri saklaması veya yasal uyumluluk
  hakkında bir beyanda bulunmaz.
- 📝 Rate limit'lere uyun.
- ✅ Sadece yetkili sistemlerde kullanın.

Ayrıntılar: [Güvenlik Değerlendirmeleri](tr/security/considerations.md) ve
[SECURITY.md](../SECURITY.md).

---

## 📈 Performans İpuçları

1. **Batch Processing**: Çok sayıda IOC için `--file` kullanın (IOC'ler art
   arda işlenir)
2. **Cache**: Tekrar eden sorgular önbellekten gelir; güncel veri için
   `--no-cache`
3. **Eşzamanlı sorgular**: Bir IOC'nin sağlayıcıları eşzamanlı sorgulanır
4. **Rate Limiting**: İstemci tarafı hız sınırları sınırlı süre bekler; dolu
   kota `rate_limited` sonucu olarak görünür

---

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen şu adımları izleyin:

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit edin (`git commit -m 'feat: add amazing feature'`)
4. Push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

Ayrıntılar: [Geliştirme ve Katkı](tr/development/contributing.md).

---

## 📜 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için
[LICENSE](../LICENSE) dosyasına bakın.

---

## ⚠️ Sorumluluk Reddi

Bu araç **yalnızca eğitim ve yetkili güvenlik testi amaçlıdır**. Yetkisiz sistemlerde kullanımı yasa dışıdır. Kullanıcılar, bu aracı kullanırken tüm geçerli yasalara uymakla yükümlüdür.

---

## 📫 İletişim

**Erkan Şahin**
- LinkedIn: [erkansahin23](https://www.linkedin.com/in/erkansahin23/)
- GitHub: [@cyb3rkan](https://github.com/cyb3rkan)

---

## 🙏 Teşekkürler

Bu proje aşağıdaki servisler sayesinde mümkün:
- [VirusTotal](https://www.virustotal.com)
- [AbuseIPDB](https://www.abuseipdb.com)
- [Shodan](https://www.shodan.io)
- [AlienVault OTX](https://otx.alienvault.com)
- [GreyNoise](https://www.greynoise.io)
- [ZeroBounce](https://www.zerobounce.net)
- [Groq](https://groq.com)

---

**⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!**
