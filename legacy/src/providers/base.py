"""
Base provider class for all threat intelligence sources
"""
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from abc import ABC, abstractmethod
from typing import Optional, Any, Dict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..config import Config


class ProviderStatus(str, Enum):
    """Provider response status"""
    SUCCESS = "success"
    ERROR = "error"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"


@dataclass
class ProviderResponse:
    """Standardized provider response"""
    provider: str
    status: ProviderStatus
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    response_time: float = 0.0
    raw_response: Optional[Dict] = None
    
    def is_success(self) -> bool:
        """Check if response was successful"""
        return self.status == ProviderStatus.SUCCESS
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "provider": self.provider,
            "status": self.status.value,
            "data": self.data,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
            "response_time": self.response_time,
        }


class BaseProvider(ABC):
    """Base class for all threat intelligence providers"""
    
    def __init__(self, api_key: str, timeout: int = Config.REQUEST_TIMEOUT_SECONDS):
        """
        Initialize provider with retry logic and TLS 1.2+ support
        
        Args:
            api_key: API key for the provider
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        
        # Configure retry strategy for better reliability
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=10
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update(self._get_headers())
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name"""
        pass
    
    @abstractmethod
    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for requests"""
        pass
    
    def _make_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
    ) -> ProviderResponse:
        """
        Make HTTP request with error handling and Windows TLS fix
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            params: Query parameters
            json_data: JSON body data
            headers: Additional headers
            
        Returns:
            ProviderResponse object
        """
        start_time = time.time()
        
        try:
            # Merge headers
            req_headers = self.session.headers.copy()
            if headers:
                req_headers.update(headers)
            
            # Make request with tuple timeout: (connect, read)
            # Longer timeout for Windows compatibility
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=req_headers,
                timeout=(15, 45),  # 15s connect, 45s read (Windows-friendly)
                verify=True  # Ensure SSL verification
            )
            
            response_time = time.time() - start_time
            
            # Handle rate limiting
            if response.status_code == 429:
                return ProviderResponse(
                    provider=self.name,
                    status=ProviderStatus.RATE_LIMITED,
                    error="Rate limit exceeded",
                    response_time=response_time,
                )
            
            # Handle errors
            if response.status_code >= 400:
                return ProviderResponse(
                    provider=self.name,
                    status=ProviderStatus.ERROR,
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                    response_time=response_time,
                )
            
            # Parse response
            try:
                data = response.json()
            except ValueError:
                data = {"raw_text": response.text}
            
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.SUCCESS,
                data=data,
                raw_response=data,
                response_time=response_time,
            )
            
        except requests.exceptions.Timeout:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.TIMEOUT,
                error=f"Request timeout after {self.timeout}s",
                response_time=time.time() - start_time,
            )
            
        except requests.exceptions.RequestException as e:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.ERROR,
                error=f"Request failed: {str(e)[:200]}",
                response_time=time.time() - start_time,
            )
    
    @abstractmethod
    def lookup_ip(self, ip: str) -> ProviderResponse:
        """Lookup IP address"""
        pass
    
    @abstractmethod
    def lookup_domain(self, domain: str) -> ProviderResponse:
        """Lookup domain"""
        pass
    
    @abstractmethod
    def lookup_hash(self, file_hash: str) -> ProviderResponse:
        """Lookup file hash"""
        pass
    
    def lookup_url(self, url: str) -> ProviderResponse:
        """Lookup URL (optional, not all providers support this)"""
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.ERROR,
            error="URL lookup not supported by this provider",
        )
    
    def __del__(self):
        """Cleanup session on deletion"""
        if hasattr(self, 'session'):
            self.session.close()
