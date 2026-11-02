"""
IOC values must never be able to alter a provider request's URL. ZeroBounce
carries the email in the form body, so even an email local part containing
``%2F..%2F``, ``?`` or ``&`` leaves the fixed endpoint untouched and cannot
inject extra form fields. The provider host is fixed, so this is request
integrity, not SSRF.
"""
from __future__ import annotations

from ioc_enricher.providers.zerobounce import ZeroBounceProvider

_ENDPOINT = "https://api.zerobounce.net/v2/validate"


def _captured(email: str) -> tuple[str, dict]:
    provider = ZeroBounceProvider(api_key="k", timeout=5)
    seen: list[tuple[str, dict]] = []

    def fake_request(method, url, **kwargs):
        seen.append((url, kwargs))
        return provider._unsupported("test")

    provider._request = fake_request  # type: ignore[method-assign]
    provider.lookup_email(email)
    return seen[0]


def test_plain_email_goes_in_the_form_body() -> None:
    url, kwargs = _captured("user@example.com")
    assert url == _ENDPOINT
    assert kwargs["form_body"] == {"api_key": "k", "email": "user@example.com"}


def test_hostile_email_cannot_change_the_url_or_add_fields() -> None:
    hostile = "a%2F..%2F..%2Fquery%3Fx&api_key=other@evil.com"
    url, kwargs = _captured(hostile)
    assert url == _ENDPOINT
    assert kwargs["form_body"] == {"api_key": "k", "email": hostile}
    assert not kwargs.get("params")
