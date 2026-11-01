# 🔧 Ağ Bağlantı Sorunları - Çözüm Rehberi

Bu rehber, sağlayıcılara bağlanılamadığında güvenlik kontrollerini kapatmadan
sorunu bulmaya yöneliktir. Güvenlik duvarını, antivirüsü veya TLS sertifika
doğrulamasını kapatmak çözüm değildir: kod TLS doğrulamasını her zaman açık
tutar (`verify=True`) ve bunu kapatacak bir ayar yoktur.

---

## ❌ Belirtiler

Bir sağlayıcıya ulaşılamadığında zenginleştirme durmaz; o sağlayıcının sonucu
bir durum taşır ve skor kalan kanıtla hesaplanır (`evidence_status` `partial`
veya `insufficient_data` olur):

| Sağlayıcı durumu / hata | Olası neden |
|-------------------------|-------------|
| `timeout` | Ağ yavaş veya engelli; `REQUEST_TIMEOUT` (30 sn) ya da `IOC_DEADLINE_SECONDS` (60 sn) doldu |
| `error` + bağlantı hatası (ör. Windows'ta `ConnectionResetError(10054, …)`) | Güvenlik duvarı, proxy, VPN veya TLS inceleyen bir ara cihaz bağlantıyı kesiyor |
| `error` + `SSLError` / `CERTIFICATE_VERIFY_FAILED` | Kurumsal TLS incelemesi (veya bazı antivirüsler) kendi sertifikasını sunuyor |
| `error` + HTTP 401 | Anahtar yanlış veya iptal edilmiş; sağlayıcı 300 sn boyunca yeniden sorgulanmaz |
| `rate_limited` | Hız bütçesi doldu veya sağlayıcı HTTP 429 döndü (kota) — ağ sorunu değil |
| Tekrarlayan `error` (çağrı yapılmadan) | 5 ardışık geçici hatadan sonra circuit breaker açıldı; 60 sn sonra tek bir deneme yapılır |

Ayrıntılar: [Rate Limiter, Zaman Aşımları ve Circuit Breaker](tr/features/rate-limiter.md).

---

## ✅ ÇÖZÜMLER (Sırayla Dene)

### 1️⃣ Temel bağlantıyı test et

```bash
# DNS çözümlemesi
nslookup www.virustotal.com

# HTTPS (Windows PowerShell'de curl yerine curl.exe kullanın)
curl -sS -o /dev/null -w "%{http_code}\n" https://www.virustotal.com

# Python requests ile, TLS doğrulaması açık
python -c "import requests; print(requests.get('https://www.virustotal.com', timeout=10).status_code)"
```

Bu komutlar hiçbir IOC veya anahtar göndermez. `curl` çalışıp Python
çalışmıyorsa sorun Python'un proxy veya sertifika ayarlarındadır (adım 2–3).

### 2️⃣ Proxy ayarlarını kontrol et

Uygulama `requests` kullanır; `requests` sistemin WinHTTP ayarlarını değil,
ortam değişkenlerini okur: `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`.

```bash
# Linux / macOS
env | grep -i _proxy

# PowerShell
Get-ChildItem Env: | Where-Object Name -like "*PROXY*"
```

Kurumsal bir proxy arkasındaysan bu değişkenleri IT ekibinin verdiği adresle
ayarla. Sistem proxy ayarlarını (`netsh winhttp reset proxy` gibi) IT ekibine
danışmadan sıfırlama — kurumsal ağ erişimini bozabilir.

### 3️⃣ TLS incelemesi / sertifika hatası

`CERTIFICATE_VERIFY_FAILED` görüyorsan araya giren bir cihaz kendi
sertifikasını sunuyordur. Doğrulamayı kapatma; bunun yerine kurumun kök
sertifikasını güvenilir hale getir:

```bash
# Kurumsal CA paketinin yolunu requests'e ver (doğrulama açık kalır)
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.pem      # Linux / macOS
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.pem"  # PowerShell
```

`certifi` veya `pip` paketlerini lock dışından güncelleme: bağımlılıklar
`requirements/` altındaki hash'li lock dosyalarından kurulur.

### 4️⃣ Güvenlik duvarı ve antivirüs

Güvenlik duvarını veya antivirüsü kapatma. Engelleme şüphesi varsa ilgili
olay kaydına bak ve Python sürecinin sağlayıcı adreslerine giden HTTPS (443)
trafiği için bir izin kuralı iste/oluştur. Kurumsal cihazlarda bu kararı
güvenlik ekibi verir.

### 5️⃣ VPN kullanıyorsan

Bazı VPN'ler API trafiğini keser veya yavaşlatır. Kurum politikası izin
veriyorsa split tunnelling ayarlarını kontrol et; politikayı aşacak şekilde
VPN'i kapatma.

### 6️⃣ Sadece çalışan provider'ları kullan

Bir sağlayıcıya ulaşılamıyorsa anahtarını `.env` içinde boş bırak; anahtarı
olmayan sağlayıcı hiç sorgulanmaz:

```bash
SHODAN_API_KEY=        # boş: sorgulanmaz
ABUSEIPDB_API_KEY=     # boş: sorgulanmaz
```

Proje kalan sağlayıcılarla çalışır. Sonuçlar daha az kanıta dayanır: bir
`LOW` sonucunu temiz saymadan önce `evidence_status` ve
`unavailable_providers` değerlerine bak.

---

## 🔍 Hangi Provider Çalışıyor?

```bash
# Hangi anahtarların yapılandırıldığı (ağ isteği yapmaz)
python -m ioc_enricher --status

# Bir dokümantasyon IP'siyle deneme — anahtar varsa IOC sağlayıcılara gönderilir
python -m ioc_enricher --no-banner --no-cache --ip 203.0.113.7 --output json
```

JSON çıktısındaki `threat_intelligence` bölümünde her sağlayıcının durumu
(`success`, `not_found`, `timeout`, `error`, `rate_limited`) ve
`risk_assessment.unavailable_providers` listesi görünür. Ayrıntı için
`LOG_LEVEL=DEBUG` ayarla; log satırları IOC'yi değil, `ipv4#…` gibi bir parmak
izini içerir ve gizli değerler maskelenir.

---

## 🆘 Hala Çalışmıyorsa?

1. **Farklı bir ağdan dene** (izin verilen bir ağdan) — sorun ağa özgü mü?
2. **Sağlayıcının durum sayfasına bak** — servis kesintisi olabilir.
3. **Anahtarı kontrol et** — HTTP 401 ağ değil, anahtar sorunudur.
4. **Hatanın tam metnini ve sağlayıcı durumunu kaydet**; issue açarken
   anahtar, token veya gerçek IOC paylaşma.
