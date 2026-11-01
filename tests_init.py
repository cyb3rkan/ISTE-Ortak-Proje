"""
Unit tests for IOC validators
"""
import pytest
from src.validators import IOCValidator, IOCType, sanitize_ioc


class TestIOCValidator:
    """Test IOC validation functions"""
    
    def test_ipv4_validation(self):
        """Test IPv4 address validation"""
        assert IOCValidator.is_ipv4("192.168.1.1") is True
        assert IOCValidator.is_ipv4("8.8.8.8") is True
        assert IOCValidator.is_ipv4("256.1.1.1") is False
        assert IOCValidator.is_ipv4("invalid") is False
    
    def test_ipv6_validation(self):
        """Test IPv6 address validation"""
        assert IOCValidator.is_ipv6("2001:0db8:85a3::8a2e:0370:7334") is True
        assert IOCValidator.is_ipv6("::1") is True
        assert IOCValidator.is_ipv6("192.168.1.1") is False
    
    def test_domain_validation(self):
        """Test domain validation"""
        assert IOCValidator.is_domain("example.com") is True
        assert IOCValidator.is_domain("sub.example.com") is True
        assert IOCValidator.is_domain("invalid") is False
        assert IOCValidator.is_domain("192.168.1.1") is False
    
    def test_url_validation(self):
        """Test URL validation"""
        assert IOCValidator.is_url("http://example.com") is True
        assert IOCValidator.is_url("https://example.com/path") is True
        assert IOCValidator.is_url("example.com") is False
    
    def test_hash_validation(self):
        """Test hash validation"""
        # MD5
        assert IOCValidator.is_md5("44d88612fea8a8f36de82e1278abb02f") is True
        assert IOCValidator.is_md5("invalid") is False
        
        # SHA1
        assert IOCValidator.is_sha1("356a192b7913b04c54574d18c28d46e6395428ab") is True
        assert IOCValidator.is_sha1("invalid") is False
        
        # SHA256
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert IOCValidator.is_sha256(sha256) is True
        assert IOCValidator.is_sha256("invalid") is False
    
    def test_email_validation(self):
        """Test email validation"""
        assert IOCValidator.is_email("user@example.com") is True
        assert IOCValidator.is_email("test.user@sub.example.com") is True
        assert IOCValidator.is_email("invalid") is False
    
    def test_ioc_type_identification(self):
        """Test IOC type identification"""
        assert IOCValidator.identify_ioc_type("192.168.1.1") == IOCType.IPV4
        assert IOCValidator.identify_ioc_type("example.com") == IOCType.DOMAIN
        assert IOCValidator.identify_ioc_type("http://example.com") == IOCType.URL
        assert IOCValidator.identify_ioc_type("user@example.com") == IOCType.EMAIL
        assert IOCValidator.identify_ioc_type("44d88612fea8a8f36de82e1278abb02f") == IOCType.MD5
    
    def test_sanitize_ioc(self):
        """Test IOC sanitization"""
        assert sanitize_ioc("hxxp://example[.]com") == "http://example.com"
        assert sanitize_ioc("192[.]168[.]1[.]1") == "192.168.1.1"
        assert sanitize_ioc("user[@]example[.]com") == "user@example.com"
    
    def test_validate(self):
        """Test complete validation"""
        valid, ioc_type, error = IOCValidator.validate("192.168.1.1")
        assert valid is True
        assert ioc_type == IOCType.IPV4
        assert error is None
        
        valid, ioc_type, error = IOCValidator.validate("invalid")
        assert valid is False
        assert ioc_type == IOCType.UNKNOWN
        assert error is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
