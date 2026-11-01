"""
Tests for ioc_enricher.core.validator
"""
import pytest

from ioc_enricher.core.validator import IOCValidator, sanitize_ioc
from ioc_enricher.models.ioc import IOCType


# ---------------------------------------------------------------------------
# sanitize_ioc
# ---------------------------------------------------------------------------

class TestSanitizeIOC:
    def test_refang_hxxp(self):
        assert sanitize_ioc("hxxp://evil.com") == "http://evil.com"

    def test_refang_hxxps(self):
        assert sanitize_ioc("hxxps://evil.com/path") == "https://evil.com/path"

    def test_refang_bracket_dot(self):
        assert sanitize_ioc("192[.]168[.]1[.]1") == "192.168.1.1"

    def test_refang_dot_word(self):
        assert sanitize_ioc("evil[dot]com") == "evil.com"

    def test_refang_at(self):
        assert sanitize_ioc("user[@]evil.com") == "user@evil.com"

    def test_refang_at_word(self):
        assert sanitize_ioc("user[at]evil.com") == "user@evil.com"

    def test_strips_whitespace(self):
        assert sanitize_ioc("  8.8.8.8  ") == "8.8.8.8"

    def test_clean_passthrough(self):
        assert sanitize_ioc("http://clean.example.com") == "http://clean.example.com"


# ---------------------------------------------------------------------------
# Type detection
# ---------------------------------------------------------------------------

class TestIOCTypeDetection:

    @pytest.mark.parametrize("value,expected", [
        ("8.8.8.8", IOCType.IPV4),
        ("1.1.1.1", IOCType.IPV4),
        ("192.168.0.1", IOCType.IPV4),
        ("2001:4860:4860::8888", IOCType.IPV6),
        ("::1", IOCType.IPV6),
        ("google.com", IOCType.DOMAIN),
        ("sub.example.co.uk", IOCType.DOMAIN),
        ("http://example.com", IOCType.URL),
        ("https://example.com/path?q=1", IOCType.URL),
        ("user@example.com", IOCType.EMAIL),
        ("test.user+filter@mail.example.com", IOCType.EMAIL),
        # Hashes
        ("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5),
        ("356a192b7913b04c54574d18c28d46e6395428ab", IOCType.SHA1),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCType.SHA256),
    ])
    def test_detect_valid(self, value: str, expected: IOCType):
        assert IOCValidator.identify(value) == expected

    @pytest.mark.parametrize("value", [
        "not_an_ioc",
        "just_text",
        "",
        "   ",
        "12345",
    ])
    def test_detect_unknown(self, value: str):
        assert IOCValidator.identify(value) == IOCType.UNKNOWN


# ---------------------------------------------------------------------------
# Full validation
# ---------------------------------------------------------------------------

class TestIOCValidation:

    def test_valid_ip_returns_ioc(self):
        ioc, err = IOCValidator.validate("8.8.8.8")
        assert ioc is not None
        assert err is None
        assert ioc.ioc_type == IOCType.IPV4

    def test_invalid_ioc_returns_error(self):
        ioc, err = IOCValidator.validate("definitely_not_an_ioc")
        assert ioc is None
        assert err is not None

    def test_empty_returns_error(self):
        ioc, err = IOCValidator.validate("")
        assert ioc is None
        assert "empty" in (err or "").lower()

    def test_whitespace_only_returns_error(self):
        ioc, err = IOCValidator.validate("   ")
        assert ioc is None

    def test_too_long_returns_error(self):
        ioc, err = IOCValidator.validate("a" * 2100)
        assert ioc is None
        assert "length" in (err or "").lower() or "exceed" in (err or "").lower()

    def test_ioc_is_immutable(self):
        ioc, _ = IOCValidator.validate("1.2.3.4")
        with pytest.raises((AttributeError, TypeError)):
            ioc.value = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Individual type checkers
# ---------------------------------------------------------------------------

class TestTypeCheckers:

    def test_is_ipv4_valid(self):
        assert IOCValidator.is_ipv4("10.0.0.1")

    def test_is_ipv4_invalid(self):
        assert not IOCValidator.is_ipv4("999.999.999.999")

    def test_is_ipv6_valid(self):
        assert IOCValidator.is_ipv6("2001:db8::1")

    def test_is_md5_valid(self):
        assert IOCValidator.is_md5("d41d8cd98f00b204e9800998ecf8427e")

    def test_is_md5_wrong_length(self):
        assert not IOCValidator.is_md5("d41d8cd9")

    def test_is_sha1_valid(self):
        assert IOCValidator.is_sha1("da39a3ee5e6b4b0d3255bfef95601890afd80709")

    def test_is_sha256_valid(self):
        assert IOCValidator.is_sha256(
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )

    def test_is_url_http(self):
        assert IOCValidator.is_url("http://example.com")

    def test_is_url_https(self):
        assert IOCValidator.is_url("https://example.com/path")

    def test_is_url_ftp_invalid(self):
        # Only http/https are considered URLs by this validator
        assert not IOCValidator.is_url("ftp://example.com")

    def test_is_email_valid(self):
        assert IOCValidator.is_email("admin@example.com")

    def test_is_email_no_tld(self):
        assert not IOCValidator.is_email("admin@localhost")

    def test_is_domain_valid(self):
        assert IOCValidator.is_domain("example.com")

    def test_is_domain_single_label(self):
        assert not IOCValidator.is_domain("localhost")

    def test_is_domain_too_long(self):
        assert not IOCValidator.is_domain("a" * 254 + ".com")


# ---------------------------------------------------------------------------
# Defang notation in any letter case
# ---------------------------------------------------------------------------

class TestRefangIgnoresCase:
    """Threat reports write hXXp://, HXXPS://, [DOT] and (At) as often as the lower-case forms."""

    @pytest.mark.parametrize("raw,expected", [
        ("hXXp://malicious.example/x", "http://malicious.example/x"),
        ("HXXPS://malicious.example/x", "https://malicious.example/x"),
        ("hxXpS://malicious.example/x", "https://malicious.example/x"),
        ("malicious[DOT]example", "malicious.example"),
        ("malicious(Dot)example", "malicious.example"),
        ("phisher[AT]malicious.example", "phisher@malicious.example"),
        ("phisher(At)malicious.example", "phisher@malicious.example"),
    ])
    def test_mixed_case_defang_patterns(self, raw, expected):
        assert sanitize_ioc(raw) == expected

    def test_the_rest_of_the_value_keeps_its_case(self):
        assert (sanitize_ioc("hXXps://Malicious[.]Example/Path/Payload.EXE")
                == "https://Malicious.Example/Path/Payload.EXE")

    @pytest.mark.parametrize("raw,expected_type", [
        ("HXXPS://malicious[DOT]example[DOT]com/payload", IOCType.URL),
        ("malicious[DOT]example[DOT]com", IOCType.DOMAIN),
        ("phisher[AT]malicious[DOT]example", IOCType.EMAIL),
        ("203[.]0[.]113[.]7", IOCType.IPV4),
        ("44D88612FEA8A8F36DE82E1278ABB02F", IOCType.MD5),
    ])
    def test_refanged_values_keep_the_detection_order(self, raw, expected_type):
        ioc, error = IOCValidator.validate(sanitize_ioc(raw))
        assert error is None
        assert ioc.ioc_type == expected_type


# ---------------------------------------------------------------------------
# Control and invisible formatting characters
# ---------------------------------------------------------------------------

# Built with chr() so this file contains no raw control characters.
_ESC, _BEL, _NUL, _DEL, _TAB = chr(0x1B), chr(0x07), chr(0x00), chr(0x7F), chr(0x09)
_C1_CSI, _RLO, _ZWSP, _BOM, _LINE_SEP = chr(0x9B), chr(0x202E), chr(0x200B), chr(0xFEFF), chr(0x2028)
_INVISIBLE = [_ESC, _BEL, _NUL, _DEL, _TAB, _C1_CSI, _RLO, _ZWSP, _BOM, _LINE_SEP]


class TestInvisibleCharactersAreRejected:
    """
    A URL could carry ESC sequences or bidi overrides that rewrite a terminal
    or make the IOC read differently from what is sent to the providers.
    """

    @pytest.mark.parametrize("char", _INVISIBLE, ids=lambda c: f"U+{ord(c):04X}")
    def test_url_with_a_control_or_format_character_is_rejected(self, char):
        ioc, error = IOCValidator.validate(f"https://malicious.example/a{char}b")
        assert ioc is None
        assert "control or invisible" in error

    @pytest.mark.parametrize("value", [
        f"203.0.113.7{_RLO}x",
        f"malicious{_ZWSP}.example.com",
        f"phisher@malicious{_ESC}.example",
        f"44d88612fea8a8f36de82e1278abb02f{_BOM}a",
    ])
    def test_other_ioc_types_are_rejected_with_the_same_reason(self, value):
        ioc, error = IOCValidator.validate(value)
        assert ioc is None
        assert "control or invisible" in error

    def test_the_error_message_does_not_echo_the_value(self):
        _, error = IOCValidator.validate(f"https://malicious.example/{_ESC}[2J")
        assert _ESC not in error
        assert "malicious.example" not in error

    @pytest.mark.parametrize("value", [
        "https://example.com/ürün",
        "https://example.com/путь?q=1",
        "https://例え.jp/パス",
    ])
    def test_ordinary_unicode_urls_stay_valid(self, value):
        ioc, error = IOCValidator.validate(value)
        assert error is None
        assert ioc.ioc_type == IOCType.URL
