"""
IOC validators for different indicator types
"""
import re
import ipaddress
from typing import Optional, Literal
from enum import Enum

class IOCType(str, Enum):
    """Supported IOC types"""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


class IOCValidator:
    """Validate and identify IOC types"""
    
    # Regex patterns
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    URL_PATTERN = re.compile(
        r'^https?://'
    )
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    
    @staticmethod
    def identify_ioc_type(ioc: str) -> IOCType:
        """
        Identify the type of IOC
        
        Args:
            ioc: The indicator to identify
            
        Returns:
            IOCType enum value
        """
        ioc = ioc.strip()
        
        # Check IP addresses
        if IOCValidator.is_ipv4(ioc):
            return IOCType.IPV4
        if IOCValidator.is_ipv6(ioc):
            return IOCType.IPV6
            
        # Check hashes
        if IOCValidator.is_md5(ioc):
            return IOCType.MD5
        if IOCValidator.is_sha1(ioc):
            return IOCType.SHA1
        if IOCValidator.is_sha256(ioc):
            return IOCType.SHA256
            
        # Check URL (before domain, as URL contains domain)
        if IOCValidator.is_url(ioc):
            return IOCType.URL
            
        # Check email
        if IOCValidator.is_email(ioc):
            return IOCType.EMAIL
            
        # Check domain
        if IOCValidator.is_domain(ioc):
            return IOCType.DOMAIN
            
        return IOCType.UNKNOWN
    
    @staticmethod
    def is_ipv4(ip: str) -> bool:
        """Check if string is valid IPv4"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_ipv6(ip: str) -> bool:
        """Check if string is valid IPv6"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_domain(domain: str) -> bool:
        """Check if string is valid domain"""
        if not domain or len(domain) > 253:
            return False
        return bool(IOCValidator.DOMAIN_PATTERN.match(domain))
    
    @staticmethod
    def is_url(url: str) -> bool:
        """Check if string is valid URL"""
        return bool(IOCValidator.URL_PATTERN.match(url))
    
    @staticmethod
    def is_email(email: str) -> bool:
        """Check if string is valid email"""
        return bool(IOCValidator.EMAIL_PATTERN.match(email))
    
    @staticmethod
    def is_md5(hash_str: str) -> bool:
        """Check if string is valid MD5 hash"""
        return bool(IOCValidator.MD5_PATTERN.match(hash_str))
    
    @staticmethod
    def is_sha1(hash_str: str) -> bool:
        """Check if string is valid SHA1 hash"""
        return bool(IOCValidator.SHA1_PATTERN.match(hash_str))
    
    @staticmethod
    def is_sha256(hash_str: str) -> bool:
        """Check if string is valid SHA256 hash"""
        return bool(IOCValidator.SHA256_PATTERN.match(hash_str))
    
    @staticmethod
    def validate(ioc: str) -> tuple[bool, IOCType, Optional[str]]:
        """
        Validate IOC and return type
        
        Args:
            ioc: The indicator to validate
            
        Returns:
            Tuple of (is_valid, ioc_type, error_message)
        """
        if not ioc or not ioc.strip():
            return False, IOCType.UNKNOWN, "IOC cannot be empty"
        
        ioc = ioc.strip()
        ioc_type = IOCValidator.identify_ioc_type(ioc)
        
        if ioc_type == IOCType.UNKNOWN:
            return False, IOCType.UNKNOWN, f"Unknown IOC type: {ioc}"
        
        return True, ioc_type, None


def sanitize_ioc(ioc: str) -> str:
    """
    Sanitize IOC by removing common defanging patterns
    
    Examples:
        hxxp://example[.]com -> http://example.com
        192[.]168[.]1[.]1 -> 192.168.1.1
    """
    ioc = ioc.strip()
    
    # Refang URLs
    ioc = ioc.replace("hxxp://", "http://")
    ioc = ioc.replace("hxxps://", "https://")
    ioc = ioc.replace("[.]", ".")
    ioc = ioc.replace("[dot]", ".")
    ioc = ioc.replace("[@]", "@")
    ioc = ioc.replace("[at]", "@")
    
    return ioc
