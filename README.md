
# İSTE Ortak Proje
## Siber Tehdit İstihbarat ve Analiz Sistemi

**Üniversite:** İskenderun Teknik Üniversitesi (İSTE)  
**Bölüm:** Bilgisayar Mühendisliği  
**Proje türü:** Üniversite ekip projesi  
**Ekip:** 4 kişi  
**Hedef teslim tarihi:** 4 Ocak 2027  
**Durum:** Planlama ve geliştirme aşamasında

---

## 📌 Proje Hakkında

Siber Tehdit İstihbarat ve Analiz Sistemi, güvenlik analistlerinin şüpheli IP adreslerini, alan adlarını, URL'leri, dosya hash değerlerini ve e-posta adreslerini farklı tehdit istihbaratı kaynakları üzerinden analiz etmesini kolaylaştırmayı amaçlayan bir yazılım projesidir.

Sistem, farklı servislerden elde edilen güvenlik verilerini tek bir platformda toplayarak standartlaştırmayı, risk seviyesini değerlendirmeyi ve anlaşılır raporlar üretmeyi hedefler.

Bu proje savunma amaçlı siber güvenlik analizine odaklanır.

## 🎯 Projenin Amacı

Geleneksel IOC (Indicator of Compromise / Uzlaşma Göstergesi) analizinde güvenlik uzmanları farklı tehdit istihbaratı platformlarını ayrı ayrı sorgulamak zorunda kalabilir.

Bu durum:

- Analiz süresini uzatır.
- Farklı veri biçimlerinin karşılaştırılmasını zorlaştırır.
- Önemli tehdit göstergelerinin gözden kaçmasına neden olabilir.
- Tekrarlanan manuel işlemleri artırır.

Projemiz bu işlemleri ortak bir analiz sürecinde birleştirerek daha hızlı, tutarlı ve anlaşılır sonuçlar sunmayı hedefler.

## 🔍 Desteklenmesi Planlanan IOC Türleri

| IOC Türü | Açıklama |
|---|---|
| IP Address | IPv4 ve IPv6 adreslerinin analizi |
| Domain | Alan adlarının güvenlik değerlendirmesi |
| URL | Şüpheli web adreslerinin incelenmesi |
| File Hash | MD5, SHA-1 ve SHA-256 değerlerinin analizi |
| Email | E-posta adreslerinin biçim ve tehdit göstergeleri açısından değerlendirilmesi |

Desteklenen sorgular, kullanılan tehdit istihbaratı servislerinin yeteneklerine göre değişebilir.

## 🛡️ Tehdit İstihbaratı Kaynakları

Sistem kapsamında aşağıdaki servislerle entegrasyon planlanmaktadır:

- **VirusTotal:** IOC'lere ilişkin güvenlik tespitleri ve itibar verileri.
- **AbuseIPDB:** IP adresleri için kötüye kullanım bildirimleri.
- **Shodan:** IP adreslerine ait ağ servisleri ve açık port bilgileri.
- **AlienVault OTX:** Açık tehdit istihbaratı ve ilişkili tehdit göstergeleri.

API anahtarları, kullanım kotaları ve sağlayıcı sınırlamaları dikkate alınacaktır.

## ⚙️ Planlanan Sistem Özellikleri

### 1. IOC Tespiti ve Doğrulama

Kullanıcıdan alınan girdinin türü otomatik olarak belirlenecek ve analiz öncesinde biçim doğrulaması yapılacaktır.

### 2. Çoklu Kaynak Entegrasyonu

IOC türüne uygun tehdit istihbaratı servisleri sorgulanacak ve sonuçlar ortak bir yapıda toplanacaktır.

### 3. Veri Standartlaştırma

Farklı servislerden gelen yanıtlar, analiz motorunun kullanabileceği ortak bir veri modeline dönüştürülecektir.

### 4. Risk Puanlama

Toplanan bulgular üzerinden 0–100 arasında risk puanı ve açıklanabilir risk seviyesi üretilecektir.

Planlanan risk seviyeleri:

- LOW — Düşük
- MEDIUM — Orta
- HIGH — Yüksek
- CRITICAL — Kritik

Risk puanları kesin zararlılık kanıtı değil, analiste yardımcı değerlendirmelerdir.

### 5. Yapay Zekâ Destekli Değerlendirme

Yapay zekâ bileşeni, mevcut tehdit istihbaratı bulgularını özetlemek, risk gerekçelerini açıklamak ve güvenlik analistine yardımcı öneriler üretmek amacıyla kullanılacaktır.

Yapay zekâ çıktıları doğrulanmış teknik bulguların yerine geçmeyecektir.

### 6. Toplu IOC Analizi

Birden fazla IOC'nin tek işlem kapsamında analiz edilmesi ve sonuçların ayrı ayrı raporlanması hedeflenmektedir.

### 7. Raporlama

Analiz sonuçlarının aşağıdaki biçimlerde sunulması planlanmaktadır:

- Terminal çıktısı
- JSON raporu
- Markdown raporu

## 🏗️ Sistem Mimarisi

Planlanan veri akışı:

```text
Kullanıcı / IOC Listesi
         |
         v
IOC Türü Tespiti ve Doğrulama
         |
         v
Tehdit İstihbaratı Sağlayıcıları
(VirusTotal / AbuseIPDB / Shodan / OTX)
         |
         v
Veri Toplama ve Standartlaştırma
         |
         v
Risk Puanlama ve Analiz
         |
         +----> Yapay Zekâ Destekli Yorum
         |
         v
Terminal / JSON / Markdown Raporu
```

Sistem modüler bir mimariyle geliştirilecek; doğrulama, API entegrasyonları, veri zenginleştirme, analiz ve raporlama bileşenleri ayrı sorumluluklara sahip olacaktır.

## 💻 Kullanılacak Teknolojiler

| Teknoloji | Kullanım Amacı |
|---|---|
| Python | Temel uygulama geliştirme |
| REST API | Tehdit istihbaratı servisleriyle iletişim |
| JSON | Veri alışverişi ve raporlama |
| Git | Sürüm kontrolü |
| GitHub | Kod paylaşımı ve Pull Request yönetimi |
| ClickUp | Görev, öncelik ve proje takvimi yönetimi |
| Otomatik testler | Yazılımın doğrulanması |

Kesin kütüphaneler ve bağımlılıklar geliştirme sürecinde belirlenecektir.

## 👥 Ekip Çalışma Düzeni

Proje dört kişilik ekip tarafından geliştirilecektir.

Her ekip üyesi kendisine atanan ClickUp görevlerini takip edecek ve GitHub üzerinde ayrı branch kullanarak geliştirme yapacaktır.

Önerilen geliştirme süreci:

1. ClickUp üzerinden görev seçilir.
2. Göreve ait branch oluşturulur.
3. Kod ve gerekli testler geliştirilir.
4. GitHub üzerinde Pull Request açılır.
5. Kod incelemesi gerçekleştirilir.
6. Uygun bulunan değişiklikler ana dala birleştirilir.
7. ClickUp görevi tamamlandı olarak işaretlenir.

**ClickUp görev akışı:**

`BACKLOG → TO DO → IN PROGRESS → IN REVIEW → COMPLETE`

Örnek branch adı:

`feature/DEV-01-ioc-detection`

## 📅 Proje Takvimi

| Aşama | Planlanan Dönem |
|---|---|
| Gereksinim analizi ve mimari | 10–22 Ekim 2026 |
| Temel modüller | 23 Ekim – 1 Kasım 2026 |
| API entegrasyonları | 2–20 Kasım 2026 |
| Analiz motoru ve raporlama | Kasım – Aralık 2026 |
| Testler ve son düzenlemeler | Aralık 2026 |
| Nihai teslim | 4 Ocak 2027 |

Detaylı görev tarihleri ve sorumluluklar ClickUp üzerinden yönetilmektedir.

## 🔐 Güvenlik ve Etik İlkeler

- Proje yalnızca savunma ve güvenlik analizi amacıyla geliştirilecektir.
- API anahtarları ve gizli bilgiler kaynak kodda tutulmayacaktır.
- Kullanılan servislerin kullanım koşullarına ve kota sınırlarına uyulacaktır.
- Analiz sonuçları kesin tehdit kanıtı olarak değerlendirilmemelidir.
- Kişisel veriler ve IOC sorguları ilgili veri koruma yükümlülüklerine uygun işlenecektir.
- Otomatik saldırı, yetkisiz erişim veya istismar işlevleri projenin kapsamında değildir.

## 🚧 Mevcut Durum

Bu repository, ekip projesinin başlangıç noktasıdır.

Şu anda gereksinim analizi, mimari tasarım ve geliştirme planlaması yürütülmektedir. Kaynak kod, testler ve kurulum yönergeleri geliştirme aşamalarında eklenecektir.

---

**İskenderun Teknik Üniversitesi — Bilgisayar Mühendisliği**

**Siber Tehdit İstihbarat ve Analiz Sistemi**
