# test_cache

## 1. Amaç

`ioc_enricher/tests/test_cache.py`, dosya önbelleğinin (`utils/cache.py`)
temel sözleşmesini denetler; yaşam döngüsü kuralları — şema sürümü, süre
sonu, budama, boyut sınırı, saat kayması, izinler —
`ioc_enricher/tests/test_cache_lifecycle.py` içindedir. Bkz.
[Önbellek Sistemi ve Rapor Saklama](../features/cache-system.md).

---

## 2. Çalıştırma

Depo kökünden, editable kurulumdan sonra:

```bash
python -m pytest ioc_enricher/tests/test_cache.py ioc_enricher/tests/test_cache_lifecycle.py -v
python -m pytest ioc_enricher/tests/test_cache_lifecycle.py -k "prune" -v
```

---

## 3. Kapsam

`test_cache.py` — `TestCache` sınıfı (9 test fonksiyonu):

| Test | Denetim |
|---|---|
| `test_get_miss_returns_none` | Bilinmeyen anahtar → `None` |
| `test_set_then_get` | Saklanan değer geri gelir |
| `test_overwrite_existing_key` | İkinci `set()` kaydı değiştirir |
| `test_invalidate_removes_entry` | `invalidate()` tek bir kaydı siler |
| `test_clear_removes_all` | `clear()` tüm kayıtları siler |
| `test_expired_entry_returns_none` | TTL'i geçmiş kayıt ıskadır |
| `test_disabled_cache_always_miss` | `enabled=False` hiçbir şey saklamaz veya döndürmez |
| `test_stats_returns_dict` | `stats()` anahtarları |
| `test_values_are_json_serialisable` | Kayıtlar pickle değil, JSON'dur |

`test_cache_lifecycle.py` — `TestEntries` ve `TestPruning` sınıfları ile iki
modül düzeyi test (14 test fonksiyonu): her kayıtta şema sürümü; kullanılamaz,
bozuk ve süresi dolmuş kayıtlar ıskadır ve silinir; atomik yazma; IOC
içermeyen debug logları; yalnızca sahibine açık dosyalar (yalnızca POSIX —
Windows'ta atlanır); süresi dolmuş dosyaların okunmadan budanması, en
eskiden başlayan boyut sınırı, yalnızca önbellek adlı dosyalar, aralık
başına en fazla bir budama, budama sırasında kaybolan dosyalar; doğrulanmamış
AI anlatısı taşıyan eski kayıt asla sunulmaz; okunamayan kayıt yeni bir
zenginleştirmeye düşer.

Testler pytest'in `tmp_path` dizinini kullanır; gerçek önbellek dizinine
hiçbir şey yazılmaz; ağ ve anahtar yoktur.

---

## 4. İlgili testler

- `tests/adapter/test_report_lifecycle.py`, `tests/adapter/test_report_store.py`
  — web rapor saklama ve temizleme.

---

## 5. İlgili Belgeler

- [Önbellek Sistemi ve Rapor Saklama](../features/cache-system.md)
