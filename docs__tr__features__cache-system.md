# Önbellek Sistemi ve Rapor Saklama

## 1. Genel Bakış

`utils/cache.py` (`Cache` sınıfı), zenginleştirme sonuçlarını JSON dosyaları
olarak saklar; böylece aynı IOC, TTL süresi içinde sağlayıcılara yeniden
sorulmaz. API üzerinden kaydedilen web raporlarının ayrı bir deposu ve saklama
kuralı vardır (bölüm 6).

Burada anlatılan davranışı `ioc_enricher/tests/test_cache_lifecycle.py` ve
`tests/adapter/test_report_lifecycle.py` kapsar.

---

## 2. Kayıtlar

- Dizin: `Config.CACHE_DIR` — kaynak kodda `ioc_enricher/data/cache/`;
  `IOC_ENRICHER_DATA_DIR` ayarlıysa `$IOC_ENRICHER_DATA_DIR/cache` (Docker
  yığını `/app/data` kullanır).
- IOC başına bir dosya, adı `<sha256(IOC)>.json` (64 hex karakter): IOC
  değeri hiçbir zaman dosya adında yer almaz.
- İçerik: `{"schema": 2, "cached_at": <epoch saniye>, "value": <sonuç>}`.
- Yazmalar atomiktir (aynı dizinde geçici dosya + yeniden adlandırma). POSIX'te
  dizin yalnızca sahibine açıktır (`0700`), dosyalar `0600`.
- Debug log satırları kayıtları IOC ile değil, anahtarlı bir parmak iziyle
  anar.

Şu kayıtlar **önbellek ıskası** sayılır ve dosyası da silinir: süresi dolmuş,
eski şemalı (örneğin AI yanıt doğrulamasından önce yazılmış), JSON nesnesi
olmayan, yarım yazılmış, değeri olmayan veya 5 dakikadan fazla ileri tarihli
kayıt. Böyle bir kayıt hiçbir zaman sonuç olarak sunulmaz.

İsabette zenginleştirici saklı sonucu yeniden doğrular, skoru ve MITRE
eşlemesini yeniden hesaplar; okuyamadığı bir kayıt uyarıyla atılır ve yeni bir
zenginleştirme çalışır. Önbellekten gelen sonuçlar `from_cache: true` taşır.

---

## 3. Boyut ve temizlik

| Değişken | Varsayılan | Anlamı |
|---|---|---|
| `ENABLE_CACHE` | `true` | `false`: `get()` hep ıskalar, `set()` hiçbir şey yapmaz. |
| `CACHE_TTL_HOURS` | `24` | Kayıt ömrü. |
| `CACHE_MAX_SIZE_MB` | `100` (1–100000) | Önbellek dizininin boyut sınırı. |

`set()` en fazla 10 dakikada bir budama tetikler (her istekte değil): süresi
dolmuş dosyalar okunmadan, değiştirilme zamanına göre silinir; ardından dizin
`CACHE_MAX_SIZE_MB` altına inene kadar en eski kayıtlar silinir. Bir saatten
eski geçici dosya artıkları da temizlenir. Yalnızca önbellek dizinindeki,
önbellek adlı dosyalar silinir — `clear()` için de aynısı geçerlidir.

---

## 4. Kullanım

```bash
python -m ioc_enricher --cache-stats     # kayıt sayısı, boyut, TTL, etkin mi
python -m ioc_enricher --clear-cache     # yalnızca önbellek kayıtlarını siler
python -m ioc_enricher --ioc 203.0.113.7 --no-cache   # tek çalıştırmada atla
```

Web API: `GET /api/v1/cache`, `entries`, `size_bytes`, `ttl_hours` döndürür
(`hits`/`misses` tutulmaz ve `null` kalır); `DELETE /api/v1/cache` yönetici
kimliği ister ve hız sınırlıdır (`IOC_WEB_CLEAR_CACHE_PER_MIN`, varsayılan 1).

```python
from ioc_enricher.utils.cache import Cache

cache = Cache(cache_dir="data/cache", ttl_hours=12, enabled=True, max_size_mb=50)
cache.set("203.0.113.7", {"example": True})
cache.get("203.0.113.7")        # değer veya None
cache.invalidate("203.0.113.7")
cache.stats()                   # {"entry_count", "total_size_kb", "ttl_hours", "enabled"}
cache.prune()                   # {"expired": n, "over_quota": m}
cache.clear()                   # silinen kayıt sayısı
```

---

## 5. Güvenlik notları

| Risk | Kontrol | Sınır |
|---|---|---|
| Dosya adında IOC | SHA-256 dosya adları | IOC dosyanın içinde yine vardır. |
| Değiştirilmiş kayıt | Şema/tip denetimleri; okunamayan kayıtlar atılır | Dizine yazabilen bir saldırgan yine de iyi biçimli bir sonuç yerleştirebilir — dizini yalnızca sahibine açık tutun. |
| Eski veya miras içerik | Süre, şema sürümü, önbellekten önce AI yanıt doğrulaması | — |
| Diskin dolması | `CACHE_MAX_SIZE_MB` budaması | Budama yalnızca sonuç yazılırken çalışır. |

Önbellek dosyaları incelenen IOC'lerin sağlayıcı sonuçlarını içerir: dizini
hassas veri olarak değerlendirin.

---

## 6. Rapor saklama ve temizleme

| Depo | Konum | Ad | Saklama |
|---|---|---|---|
| Web raporları (API isteklerinde `save_report_format`) | `<REPORTS_DIR>/web/` | `<UUID>.json` veya `<UUID>.md.meta.json` yan dosyasıyla `<UUID>.md` | `REPORT_RETENTION_DAYS` (varsayılan `30`) ve `REPORT_MAX_TOTAL_MB` (varsayılan `200`, önce en eskiler silinir) |
| CLI raporları (`--save`) | `<REPORTS_DIR>/` | `ioc_<tür>_<YYYYMMDDTHHMMSSZ>_<8 hex>.<uzantı>` | **Yok** — otomatik budanmaz |

`<REPORTS_DIR>`, kaynak kodda `ioc_enricher/reports/`; `IOC_ENRICHER_REPORTS_DIR`
ayarlıysa o dizindir (Docker yığını `/app/reports` kullanır).

Web raporları: dosya adını çağıran seçmez (UUID4 kimliği üretilir), saklanan
içerik API'nin döndürdüğü güvenli DTO ile aynıdır, her rapor bir şema sürümü
taşır ve okunurken doğrulanır, yazmalar atomik ve yalnızca sahibine açıktır
(POSIX), budama `save_report` içinden en fazla saatte bir çalışır ve yalnızca
UUID adlı rapor dosyalarına dokunur.

CLI raporlarının adında ham IOC hiçbir zaman bulunmaz, dosyalar yalnızca
sahibine açık oluşturulur (POSIX) ve var olan bir dosyanın üzerine asla
yazılmaz (bkz. [CLI Kullanımı](../cli/usage.md)). Artık gerekmediklerinde
kendiniz silin.

---

## 7. İlgili Belgeler

- [Zenginleştirme Motoru](enrichment-engine.md)
- [CLI Kullanımı](../cli/usage.md)
- [Güvenlik Değerlendirmeleri](../security/considerations.md)
