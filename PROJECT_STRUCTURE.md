# IOC-Enricher — Project Structure Skeleton

Bu arşiv, kullanıcının paylaştığı IOC-Enricher ZIP dosyasındaki gerçek ve desteklenen proje yerleşimi temel alınarak hazırlanmış **klasör iskeletidir**. Uygulama kaynak kodları bu pakete kopyalanmamıştır; klasörlerin Git tarafından izlenebilmesi için `.gitkeep` dosyaları eklenmiştir.

## Ana bileşenler

- `ioc_enricher/ioc_enricher/`: Kanonik Python paketi. CLI, analiz motoru, IOC doğrulama, risk puanlama, MITRE eşlemesi, sağlayıcılar, raporlama, yardımcı modüller ve web katmanı burada bulunur.
- `frontend/`: React + Vite + TypeScript kullanıcı arayüzü; kaynak, E2E ve frontend test dizinleri burada bulunur.
- `ioc_enricher/tests/`: Python paketinin birim testleri.
- `tests/`: API, adapter, CLI, entegrasyon ve güvenlik testleri.
- `docs/`: Türkçe ve İngilizce proje belgeleri.
- `docker/`: Backend/frontend Dockerfile'ları, Compose ve Nginx yapılandırması.
- `requirements/`: Bağımlılık kilit ve gereksinim dosyalarının yeri.
- `legacy/`: Eski prototip kodu için ayrılmış alan. Yeni geliştirme buraya yapılmamalıdır.

## Önemli mimari not

Orijinal arşivde ayrı bir `backend/` kök klasörü yoktur. Python backend'in kanonik kaynak kodu `ioc_enricher/ioc_enricher/` yolundadır. Bu nedenle yeni bir `backend/` ağacı oluşturulmadı; mevcut modül yolları korundu.

## Ekip çalışması için öneri

1. Her ekip üyesi kendi branch'inde çalışsın.
2. Dosyaları bu iskeletteki gerçek hedef yollarına yerleştirsin; yalnızca dosyaları teslim etmek için ikinci bir `frontend/` veya `backend/` kökü yaratmasın.
3. Herkes kendi branch'ine push edip Pull Request açsın.
4. `main` branch'ine birleştirmeden önce import yolları, frontend build, testler ve güvenlik kontrolleri incelensin.

## Güvenlik ve temizlik

Aşağıdakiler bilerek bu iskelete eklenmedi:

- `.env`, `frontend/.env.local` ve diğer yerel secret dosyaları
- `.mcp.json` ve yerel AI/IDE yapılandırmaları
- `.venv`, `node_modules`, `__pycache__`, test cache'leri
- `dist`, build ve test-result çıktıları
- loglar, gerçek IOC verileri ve oluşturulmuş raporlar

Gerçek API anahtarları veya token'lar Git'e gönderilmemelidir. Gerekli değişken adları, güvenli ve boş değerli örneklerle `.env.example` üzerinden ayrıca yönetilmelidir.
