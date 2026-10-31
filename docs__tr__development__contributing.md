# Geliştirme ve Katkı

## 1. Genel Bakış

Bu belge, IOC Enricher'a katkı için geliştirme kurulumunu, proje yapısını,
sağlayıcı eklemeyi ve test ile güvenlik kurallarını anlatır.

---

## 2. Geliştirme Ortamı Kurulumu

### Gereksinimler

- Python 3.11+ (CI ve backend imajı 3.12 kullanır)
- Arayüz için Node.js 24 ve npm
- Git

### Kurulum

```bash
# Depoyu kopyalayın
git clone https://github.com/your-org/ioc-enricher-agent.git
cd ioc-enricher-agent

# Sanal ortam oluşturun
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate      # Windows

# Hash'li test lock'unu ve paketi (editable) yükleyin
python -m pip install -r requirements.txt
python -m pip install --no-deps -e .

# Ortamı yapılandırın (testler için gerekmez)
cp .env.example .env
# .env'i düzenleyin — sağlayıcı API anahtarını yalnızca manuel test için ekleyin

# Arayüz
cd frontend && npm ci && cd ..
```

### Kurulumu Doğrulama

```bash
# Backend test paketi (API anahtarı gerekmez)
python -m pytest tests ioc_enricher/tests -q

# Sağlayıcı durumunu kontrol edin (ağ isteği yapmaz)
python -m ioc_enricher --status

# Bir dokümantasyon IOC'sini zenginleştirin (varsa yapılandırılmış sağlayıcılara gönderilir)
python -m ioc_enricher --ip 203.0.113.7
```

Editable kurulum yoksa depo kökünden `pytest` ve `python -m pytest`,
`tests/` ağacını içeren çalıştırmalarda çalışır (oradaki `conftest.py`
paket yolunu ekler); yalnızca `ioc_enricher/tests` için düz `pytest`
kullanın veya `PYTHONPATH=ioc_enricher` ayarlayın.

---

## 3. Proje Yapısı

```
ioc_enricher/
├── ioc_enricher/           # Ana Python paketi
│   ├── __init__.py         # Genel API dışa aktarımları (IOCEnricher)
│   ├── __main__.py         # python -m ioc_enricher giriş noktası
│   ├── enricher.py         # Boru hattı yöneticisi (IOCEnricher)
│   ├── core/               # validator, aggregator, scoring, analyzer (AI), eicar
│   ├── providers/          # base.py, _fields.py (ayrıştırma yardımcıları), altı sağlayıcı
│   ├── models/             # ioc.py, result.py
│   ├── mitre/              # mapper.py
│   ├── reports/            # generator.py
│   ├── utils/              # config, logger, cache, rate_limiter, fileio
│   ├── web/                # service, schemas (DTO'lar), mappers, report_store, settings,
│   │                       # api/ (FastAPI uygulaması, middleware, router'lar, güvenlik)
│   └── cli/                # main.py
└── tests/                  # paket birim testleri
tests/                      # adapter, api, cli, security testleri (+ entegrasyon sunucusu)
frontend/                   # React uygulaması, Vitest testleri, Playwright E2E
```

---

## 4. Yeni Sağlayıcı Ekleme

### Adım 1 — Sağlayıcı modülünü oluşturun

```python
# providers/new_provider.py
from typing import Dict, FrozenSet

from ..models import IOCType, ProviderResult
from ._fields import count, text
from .base import BaseProvider


class NewProvider(BaseProvider):
    BASE_URL = "https://api.newprovider.example"   # sabit, HTTPS OLMALI
    SUPPORTED_IOC_TYPES: FrozenSet[IOCType] = frozenset({IOCType.IPV4, IOCType.IPV6})

    @property
    def name(self) -> str:
        return "NewProvider"            # aynı zamanda rate limiter bucket adı

    def _get_headers(self) -> Dict[str, str]:
        return {"X-Api-Key": self._api_key, "Accept": "application/json"}

    def lookup_ip(self, ip: str) -> ProviderResult:
        result = self._request("GET", f"{self.BASE_URL}/ip/{ip}")
        if not result.is_success():
            return result               # error / timeout / rate_limited, zaten açıklanmış
        raw = result.data
        if not isinstance(raw, dict):
            return self._invalid(result, "body is not an object")
        result.data = {
            "threat_score": count(raw.get("score")),      # yoksa veya tipi yanlışsa None
            "category": text(raw.get("category"), 64),
        }
        return result
```

- Kurucu miras alınır: `BaseProvider(api_key, timeout=30,
  rate_limiter=None)`.
- `_request(method, url, *, params=None, json_body=None)` bir
  `ProviderResult` döndürür; HTTPS'i, hız sınırını, IOC başına süre
  bütçesini, yeniden denemeleri ve circuit breaker'ı uygular. `requests`'i
  asla doğrudan çağırmayın.
- Desteklenmeyen türler için lookup yazmayın: temel sınıf `unsupported`
  sonucu döndürür.
- `_fields` yardımcılarıyla (`text`, `flag`, `count`, `text_list`) savunmacı
  ayrıştırın: olmayan veya tipi yanlış bir değer `0` ya da `False` değil,
  `None` olur. URL yoluna konan IOC değerlerini percent-encode edin.

### Adım 2 — Yapılandırma

`utils/config.py` dosyasına (ve `provider_status()` içine)
`NEW_PROVIDER_API_KEY` ekleyin; `.env.example` dosyasına boş bir
`NEW_PROVIDER_API_KEY=` satırı ekleyin (`tests/security/test_example_config.py`
sırların boş kalmasını şart koşar).

### Adım 3 — `IOCEnricher` içinde oluşturun

`IOCEnricher._init_providers()` içindeki `candidates` listesine
`(cfg.NEW_PROVIDER_API_KEY, NewProvider)` ekleyin; anahtarı olmayan
sağlayıcılar oluşturulmaz.

### Adım 4 — Hız sınırı

`utils/rate_limiter.py` içindeki `_PROVIDER_LIMITS` sözlüğüne
`"NewProvider": (rpm, burst)` ekleyin; aksi hâlde `_default` bucket'ı
(30/dk, burst 5) uygulanır. Operatörler `PROVIDER_RATE_LIMITS` ile geçersiz
kılabilir.

### Adım 5 — Puanlama

`core/scoring.py` içine üst sınırı olan bir `_score_new_provider(...)` katkısı
ve `ScoreBreakdown` (`models/result.py`) içine bir alan ekleyin. Kanıt
anlamını koruyun: `not_found` "kanıt yok" demektir ve erişilemeyen bir
sağlayıcı temiz bir yanıt olarak değil, `unavailable_providers` içinde
görünmelidir.

### Adım 6 — Web API ve AI allowlist'leri

- `web/mappers.py` `_PROVIDER_SAFE_FIELDS`: API'nin döndürebileceği alanları
  listeleyin. Listede olmayan bir sağlayıcı yalnızca `available_fields`
  (değerler olmadan adlar) olarak görünür. Arayüz yeni alanları kullanıyorsa
  `frontend/src/types/api.ts` dosyasına da ekleyin.
- `core/analyzer.py` `_AI_PROVIDER_FIELDS`: AI katmanının görebileceği
  yalnızca yapılandırılmış, hassas olmayan olguları listeleyin. Kayıt yoksa
  sağlayıcıdan modele hiçbir şey ulaşmaz; serbest metin yalnızca alıntılanan
  güvenilmeyen metin yolundan gitmelidir.

### Adım 7 — Test yazın

```python
# ioc_enricher/tests/test_providers.py
from unittest.mock import MagicMock

def test_new_provider_parsing():
    provider = NewProvider(api_key="fake-test-key")
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"score": 75, "category": "scanner"}
    resp.text = str(resp.json.return_value)
    provider._session.request = MagicMock(return_value=resp)   # gerçek HTTP yok
    result = provider.lookup_ip("203.0.113.7")
    assert result.is_success()
    assert result.data["threat_score"] == 75
```

Yanıt taklidini `ioc_enricher/tests/test_providers.py` içindeki mevcut
`_mock_response()` yardımcısından alın; gerekiyorsa
`tests/adapter/test_api_contract.py` dosyasına sözleşme,
`ioc_enricher/tests/test_provider_limits.py` dosyasına sınır senaryoları
ekleyin.

### Adım 8 — Belgeler

`docs/en/providers/<ad>.md` ve `docs/tr/providers/<ad>.md` ekleyin;
sağlayıcı genel bakışını, README tablolarını ve `.env.example` dosyasını
güncelleyin.

---

## 5. Kod Stili

- **Python sürümü:** 3.11+
- **Biçimlendirme:** PEP 8'e uyun.
- **Tip ipuçları:** Tüm genel fonksiyon imzaları tip ipucu içermelidir.
- **Dataclass'lar:** Değer nesneleri dataclass'tır (`IOC` frozen'dır).
- **Hata yönetimi:** Sağlayıcı `lookup_*()` yöntemlerinden istisna
  sızdırmayın — açık bir durumla `ProviderResult` döndürün.
- **Loglama:** `utils/logger.py` içindeki `get_logger(__name__)` kullanın —
  tanılama için asla `print()` kullanmayın; IOC'leri değeriyle değil
  `ioc_ref()` ile anın.
- **Sabit kodlanmış sır yok:** API anahtarları yalnızca ortam
  değişkenlerinden gelir.

---

## 6. Test Gereksinimleri

- Tüm yeni kodlar test içermelidir; bir hata düzeltmesi, düzeltmeden önce
  başarısız olan bir test içerir.
- Testler gerçek HTTP çağrısı yapmamalı ve API anahtarı gerektirmemelidir.
- Pull request göndermeden önce CI komutunu çalıştırın:

```bash
python -m pytest ioc_enricher/tests tests/adapter tests/cli tests/api tests/security \
  --cov=ioc_enricher --cov-report=term-missing --cov-fail-under=80 -q
cd frontend && npm run test && npm run build
```

CI, coverage %80'in altına düşerse başarısız olur; bir değişiklikle
coverage'ı düşürmeyin.

---

## 7. Commit ve Pull Request Yönergeleri

- Geleneksel commit biçimini kullanın: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`
- Her PR tek bir konuyu ele almalıdır (bir özellik, bir hata, bir sağlayıcı).
- Her hata düzeltmesi için bir test ekleyin — test düzeltmeden önce başarısız, sonra başarılı olmalıdır.
- Her yeni özellik veya sağlayıcı için `docs/` altındaki belgeleri (İngilizce ve Türkçe) güncelleyin.
- Değişikliğinizin güvenlik etkileri varsa `SECURITY.md` dosyasını güncelleyin.
- Bağımlılık lock dosyalarını elle değiştirmeyin; `requirements.txt` içinde
  anlatıldığı gibi yeniden üretin.

---

## 8. Katkıda Bulunanlar için Güvenlik Yönergeleri

- API anahtarlarını veya token'ları asla loglamayın. Logger'ın maskelemesi
  bir güvenlik ağıdır, sır loglamaya izin değildir.
- Sağlayıcı temel URL'lerini asla kullanıcı yapılandırmasından almayın —
  HTTPS sağlayıcı uç noktalarını sabit kodlayın.
- HTTP çağrıları için her zaman `BaseProvider._request()` kullanın.
- Sağlayıcı yanıtlarını her zaman savunmacı biçimde ayrıştırın (`_fields`
  yardımcıları, tip denetimleri); her sağlayıcı metnini güvenilmeyen metin
  olarak ele alın.
- Arayüzde sağlayıcı, AI veya rapor metnini asla HTML olarak göstermeyin
  (`dangerouslySetInnerHTML` yasaktır ve CI'da denetlenir).
- Bandit'i CI'daki gibi, kilitli araç dosyasından çalıştırın:

```bash
python -m pip install --require-hashes -r requirements/tools.txt
bandit -r ioc_enricher/ioc_enricher --exclude ioc_enricher/ioc_enricher/tests \
  --severity-level medium --confidence-level medium
```

CI ayrıca lock dosyaları üzerinde engelleyici `pip-audit --strict` ve
`npm audit --audit-level=low` çalıştırır; ikisi de ağ erişimi gerektirir.

---

## 9. İlgili Belgeler

- [Mimari Genel Bakış](../architecture/overview.md)
- [Sağlayıcı Genel Bakışı](../providers/overview.md)
- [Güvenlik Değerlendirmeleri](../security/considerations.md)
- [Test Belgeleri](../tests/test_providers.md)
