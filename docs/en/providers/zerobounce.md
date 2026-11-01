# ZeroBounce Provider

## 1. Overview

`providers/zerobounce.py` validates e-mail addresses with
[ZeroBounce](https://www.zerobounce.net/docs/email-validation-api-quickstart/v2-validate-emails).
ZeroBounce is a deliverability and list-hygiene service: it says whether an
address is valid, a spam trap, a known abuser or a toxic / disposable
address, and how old the e-mail domain is. It contributes up to 5 of the 100
score points.

ZeroBounce has no breach or phishing-report data, so it does not say whether
credentials leaked or whether an address sent phishing.

---

## 2. Request

`POST https://api.zerobounce.net/v2/validate` with an
`application/x-www-form-urlencoded` body of `api_key` and `email`. The key
and the address never appear in the URL (so no URL-logging layer sees the
key), and an address containing `&`, `?` or `%2F` cannot add or alter
request fields. The provider is created only when `ZEROBOUNCE_API_KEY` is
set. Client-side pacing: 60 requests per minute, burst 10.

Each validation spends one ZeroBounce credit (`unknown` results are free).
Results are cached like every other provider answer, which keeps repeat
look-ups free.

An e-mail address is personal data: it is sent as is to ZeroBounce and, when
the AI layer is on, to Groq. Logs show it only as `<email>` or a keyed
fingerprint.

---

## 3. Normalised data

| Field | Type |
|---|---|
| `status` | one of `valid`, `invalid`, `catch-all`, `unknown`, `spamtrap`, `abuse`, `do_not_mail` (lower-cased) |
| `sub_status` | e.g. `toxic`, `disposable`, `role_based`, `mailbox_not_found` (lower-cased, `""` when none) |
| `free_email`, `catchall_domain` | JSON boolean, else `null` |
| `mx_found` | `true` / `false` (ZeroBounce sends the strings `"true"` / `"false"`), else `null` |
| `domain_age_days` | non-negative integer (sent as a digit string), else `null` |
| `domain`, `mx_record`, `smtp_provider`, `did_you_mean`, `processed_at` | text, else `null` |

The owner's name, gender and IP geo-location fields of the answer are never
stored.

The web API returns `status`, `sub_status`, `free_email`,
`catchall_domain`, `mx_found`, `domain_age_days`, `smtp_provider` and
`did_you_mean`; a `null` stays `null` (unknown, shown as "—"). The AI layer
receives `status`, `sub_status`, `free_email`, `catchall_domain`,
`mx_found`, `smtp_provider`, `domain_age_days` and `processed_at` as facts;
hostnames and the typo suggestion never reach the prompt.

---

## 4. Statuses

| Situation | Status |
|---|---|
| Answer with a documented `status` | `success` |
| No / undocumented `status` | `error` ("Invalid response from ZeroBounce: no documented status") — without a verdict nothing can be judged |
| `{"error": …}` (bad key or no credits; HTTP 200) | `error`; the provider pauses for 300 s like after a 401, and the provider's text is not echoed |
| HTTP 404 | `not_found` |
| HTTP 401, 403 … | `error` (`HTTP <code>`); 401 also pauses the provider for 300 s |
| HTTP 429 | `rate_limited`, provider paused |

ZeroBounce blocks a key for an hour after 200 bad-key requests in an hour;
the 300 s pause keeps the client well under that.

---

## 5. Scoring

| Signal | Points |
|---|---|
| `sub_status` = `toxic` (known for abuse/spam, may be bot-created) | +3 |
| `status` = `spamtrap` | +2 |
| `status` = `abuse` (known complainer) | +1 |
| `sub_status` = `disposable` | +1 |
| `domain_age_days` < 30 | +1 |
| Total | capped at 5 |

`invalid`, `catch-all`, `unknown` and `role_based` are deliverability facts,
not threat signals: they score 0 and stay visible as provider data.

A toxic address maps to MITRE T1566 Phishing with basis `contextual` — it
fits phishing delivery but is not a phishing report. No other verdict maps
to ATT&CK.

---

## 6. Caveats

- Disposable and free-provider addresses are common for legitimate privacy
  reasons; read them together with the other providers.
- A `valid` address is deliverable, not trustworthy: attackers use real
  mailboxes.
- ZeroBounce cannot see delivery logs: a clean result does not clear a
  phishing message.

---

## 7. Related

- [Provider Overview](overview.md)
- [Risk Scoring](../scoring/risk-scoring.md)
- [MITRE Mapping](../features/mitre-mapping.md)
- [Test: test_providers](../tests/test_providers.md)
