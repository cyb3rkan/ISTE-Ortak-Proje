"""
IOC data models — strongly-typed representations for every indicator type.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class IOCType(str, Enum):
    """Supported Indicator of Compromise types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"

    # Convenience groupings
    @classmethod
    def ip_types(cls) -> tuple["IOCType", ...]:
        return (cls.IPV4, cls.IPV6)

    @classmethod
    def hash_types(cls) -> tuple["IOCType", ...]:
        return (cls.MD5, cls.SHA1, cls.SHA256)


@dataclass(frozen=True)
class IOC:
    """
    Immutable representation of a validated Indicator of Compromise.

    Attributes:
        value:      The raw (sanitized) indicator string.
        ioc_type:   Detected IOC type.
    """

    value: str
    ioc_type: IOCType

    def is_ip(self) -> bool:
        return self.ioc_type in IOCType.ip_types()

    def is_hash(self) -> bool:
        return self.ioc_type in IOCType.hash_types()

    def __str__(self) -> str:  # noqa: D401
        return self.value
