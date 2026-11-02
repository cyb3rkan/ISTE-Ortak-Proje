"""
VirusTotal API Provider
https://developers.virustotal.com/reference/overview
"""
from typing import Dict, Optional
from .base import BaseProvider, ProviderResponse, ProviderStatus


class VirusTotalProvider(BaseProvider):
    """VirusTotal threat intelligence provider"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    @property
    def name(self) -> str:
        return "VirusTotal"
    
    def _get_headers(self) -> Dict[str, str]:
        """Get VirusTotal API headers"""
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }
    
    def lookup_ip(self, ip: str) -> ProviderResponse:
        """
        Lookup IP address reputation
        
        Args:
            ip: IP address to lookup
            
        Returns:
            ProviderResponse with IP reputation data
        """
        url = f"{self.BASE_URL}/ip_addresses/{ip}"
        response = self._make_request("GET", url)
        
        if not response.is_success():
            return response
        
        # Parse VirusTotal response
        try:
            data = response.data.get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            parsed_data = {
                "ip": ip,
                "country": attributes.get("country"),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "reputation": attributes.get("reputation", 0),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "whois": attributes.get("whois"),
            }
            
            response.data = parsed_data
            
        except (KeyError, AttributeError) as e:
            response.status = ProviderStatus.ERROR
            response.error = f"Failed to parse VirusTotal response: {str(e)}"
        
        return response
    
    def lookup_domain(self, domain: str) -> ProviderResponse:
        """
        Lookup domain reputation
        
        Args:
            domain: Domain name to lookup
            
        Returns:
            ProviderResponse with domain reputation data
        """
        url = f"{self.BASE_URL}/domains/{domain}"
        response = self._make_request("GET", url)
        
        if not response.is_success():
            return response
        
        try:
            data = response.data.get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            parsed_data = {
                "domain": domain,
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "reputation": attributes.get("reputation", 0),
                "categories": attributes.get("categories", {}),
                "creation_date": attributes.get("creation_date"),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "registrar": attributes.get("registrar"),
            }
            
            response.data = parsed_data
            
        except (KeyError, AttributeError) as e:
            response.status = ProviderStatus.ERROR
            response.error = f"Failed to parse VirusTotal response: {str(e)}"
        
        return response
    
    def lookup_hash(self, file_hash: str) -> ProviderResponse:
        """
        Lookup file hash
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
            
        Returns:
            ProviderResponse with file analysis data
        """
        url = f"{self.BASE_URL}/files/{file_hash}"
        response = self._make_request("GET", url)
        
        if not response.is_success():
            # Check if file not found
            if response.status == ProviderStatus.ERROR and "404" in str(response.error):
                response.status = ProviderStatus.NOT_FOUND
                response.error = "File hash not found in VirusTotal database"
            return response
        
        try:
            data = response.data.get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            parsed_data = {
                "hash": file_hash,
                "md5": attributes.get("md5"),
                "sha1": attributes.get("sha1"),
                "sha256": attributes.get("sha256"),
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "file_type": attributes.get("type_description"),
                "file_size": attributes.get("size"),
                "first_submission_date": attributes.get("first_submission_date"),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "names": attributes.get("names", []),
                "reputation": attributes.get("reputation", 0),
            }
            
            response.data = parsed_data
            
        except (KeyError, AttributeError) as e:
            response.status = ProviderStatus.ERROR
            response.error = f"Failed to parse VirusTotal response: {str(e)}"
        
        return response
    
    def lookup_url(self, url: str) -> ProviderResponse:
        """
        Lookup URL reputation
        
        Args:
            url: URL to lookup
            
        Returns:
            ProviderResponse with URL analysis data
        """
        # VirusTotal requires URL to be base64 encoded (URL-safe)
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        lookup_url = f"{self.BASE_URL}/urls/{url_id}"
        response = self._make_request("GET", lookup_url)
        
        if not response.is_success():
            return response
        
        try:
            data = response.data.get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            parsed_data = {
                "url": url,
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "last_analysis_date": attributes.get("last_analysis_date"),
                "reputation": attributes.get("reputation", 0),
                "categories": attributes.get("categories", {}),
            }
            
            response.data = parsed_data
            
        except (KeyError, AttributeError) as e:
            response.status = ProviderStatus.ERROR
            response.error = f"Failed to parse VirusTotal response: {str(e)}"
        
        return response
