# ZeroBounce Sağlayıcısı

## 1. Genel Bakış

`providers/zerobounce.py`, e-posta adreslerini
[ZeroBounce](https://www.zerobounce.net/docs/email-validation-api-quickstart/v2-validate-emails)
ile doğrular. ZeroBounce bir teslim edilebilirlik ve liste hijyeni
servisidir: adresin geçerli olup olmadığını, spam tuzağı, bilinen bir
kötüye kullanıcı ya da toxic / tek kullanımlık bir adres olup olmadığını ve
e-posta alan adının yaşını bildirir. 100 skor puanının en fazla 5'ini katar.

ZeroBounce'ta sızıntı veya kimlik avı raporu verisi yoktur; kimlik
bilgilerinin sızıp sızmadığını ya da adresin kimlik avı gönderip
göndermediğini söylemez.

---

## 2. İstek

`POST https://api.zerobounce.net/v2/validate`, gövde
`application/x-www-form-urlencoded` biçiminde `api_key` ve `email`
alanlarıdır. Anahtar ve adres URL'de hiç yer almaz (böylece URL kaydeden
hiçbir katman anahtarı görmez); `&`, `?` veya `%2F` içeren bir adres istek
alanı ekleyemez ya da değiştiremez. Sağlayıcı yalnızca `ZEROBOUNCE_API_KEY`
tanımlıysa oluşturulur. İstemci tarafı hız sınırı: dakikada 60 istek,
burst 10.

Her doğrulama bir ZeroBounce kredisi harcar (`unknown` sonuçlar ücretsizdir).
Sonuçlar diğer sağlayıcı yanıtları gibi önbelleğe alınır; tekrar eden
sorgular kredi harcamaz.

E-posta adresi kişisel veridir: ZeroBounce'a ve AI katmanı açıksa Groq'a
olduğu gibi gönderilir. Loglarda yalnızca `<email>` ya da anahtarlı bir
parmak izi olarak görünür.

---

## 3. Normalize edilmiş veri

| Alan | Tür |
|---|---|
| `status` | `valid`, `invalid`, `catch-all`, `unknown`, `spamtrap`, `abuse`, `do_not_mail` değerlerinden biri (küçük harfe çevrilir) |
| `sub_status` | ör. `toxic`, `disposable`, `role_based`, `mailbox_not_found` (küçük harf, yoksa `""`) |
| `free_email`, `catchall_domain` | JSON boolean, değilse `null` |
| `mx_found` | `true` / `false` (ZeroBounce `"true"` / `"false"` metni gönderir), değilse `null` |
| `domain_age_days` | negatif olmayan tam sayı (rakam metni olarak gelir), değilse `null` |
| `domain`, `mx_record`, `smtp_provider`, `did_you_mean`, `processed_at` | metin, değilse `null` |

Yanıttaki sahip adı, cinsiyet ve IP konum alanları hiçbir zaman saklanmaz.

Web API `status`, `sub_status`, `free_email`, `catchall_domain`,
`mx_found`, `domain_age_days`, `smtp_provider` ve `did_you_mean` döndürür;
`null` değer `null` kalır (bilinmiyor, "—" olarak gösterilir). AI katmanı
`status`, `sub_status`, `free_email`, `catchall_domain`, `mx_found`,
`smtp_provider`, `domain_age_days` ve `processed_at` alanlarını olgu olarak
alır; host adları ve yazım önerisi prompt'a hiç girmez.

---

## 4. Durumlar

| Durum | Sonuç |
|---|---|
| Belgelenmiş bir `status` içeren yanıt | `success` |
| `status` yok / belgelenmemiş | `error` ("Invalid response from ZeroBounce: no documented status") — karar olmadan hiçbir şey değerlendirilemez |
| `{"error": …}` (geçersiz anahtar veya kredi yok; HTTP 200) | `error`; sağlayıcı 401 sonrasındaki gibi 300 sn duraklar, sağlayıcının metni aktarılmaz |
| HTTP 404 | `not_found` |
| HTTP 401, 403 … | `error` (`HTTP <kod>`); 401 ayrıca sağlayıcıyı 300 sn duraklatır |
| HTTP 429 | `rate_limited`, sağlayıcı duraklatılır |

ZeroBounce, bir saat içinde 200 hatalı anahtar isteğinden sonra anahtarı bir
saat engeller; 300 sn'lik duraklama istemciyi bu sınırın çok altında tutar.

---

## 5. Puanlama

| Sinyal | Puan |
|---|---|
| `sub_status` = `toxic` (kötüye kullanım/spam ile bilinen, bot hesabı olabilir) | +3 |
| `status` = `spamtrap` | +2 |
| `status` = `abuse` (bilinen şikâyetçi) | +1 |
| `sub_status` = `disposable` | +1 |
| `domain_age_days` < 30 | +1 |
| Toplam | en fazla 5 |

`invalid`, `catch-all`, `unknown` ve `role_based` tehdit sinyali değil,
teslim edilebilirlik bilgisidir: 0 puan alır ve sağlayıcı verisi olarak
görünür kalır.

Toxic bir adres MITRE T1566 Phishing ile `contextual` dayanakla eşlenir —
kimlik avı teslimatına uyar ama bir kimlik avı raporu değildir. Diğer
kararlar ATT&CK ile eşlenmez.

---

## 6. Uyarılar

- Tek kullanımlık ve ücretsiz sağlayıcı adresleri meşru gizlilik
  nedenleriyle de yaygındır; diğer sağlayıcılarla birlikte okuyun.
- `valid` bir adres teslim edilebilir demektir, güvenilir değil:
  saldırganlar gerçek posta kutuları kullanır.
- ZeroBounce teslimat kayıtlarını göremez: temiz bir sonuç bir kimlik avı
  mesajını aklamaz.

---

## 7. İlgili

- [Sağlayıcılara Genel Bakış](overview.md)
- [Risk Puanlama](../scoring/risk-scoring.md)
- [MITRE Eşleme](../features/mitre-mapping.md)
- [Test: test_providers](../tests/test_providers.md)
