"""
AlienVault OTX (Open Threat Exchange) API Provider
https://otx.alienvault.com/api
"""
from typing import Dict
from .base import BaseProvider, ProviderResponse, ProviderStatus


class OTXProvider(BaseProvider):
    """AlienVault OTX threat intelligence provider"""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    @property
    def name(self) -> str:
        return "AlienVault OTX"
    
    def _get_headers(self) -> Dict[str, str]:
        """Get OTX API headers"""
        return {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
        }
    
    def lookup_ip(self, ip: str) -> ProviderResponse:
        """
        Lookup IP address reputation
        
        Args:
            ip: IP address to lookup
            
        Returns:
            ProviderResponse with IP threat intelligence
        """
        url = f"{self.BASE_URL}/indicators/IPv4/{ip}/general"
        response = self._make_request("GET", url)
        
        if not response.is_success():
            return response
        
        try:
            data = response.data
            
            # Get pulse information
            pulse_url = f"{self.BASE_URL}/indicators/IPv4/{ip}/malware"
            pulse_response = self._make_request("GET", pulse_url)
            
            pulses = []
            pulse_count = 0
            
            if pulse_response.is_success():
                pulse_data = pulse_response.data.get("data", [])
                pulse_count = len(pulse_data)
                pulses = [
                    {
                        "name": p.get("detections", {}).get("name", "Unknown"),
                        "hash": p.get("hash"),
                    }
                    for p in pulse_data[:5]  # Top 5 malware detections
                ]
            
            parsed_data = {
                "ip": ip,
                "reputation": data.get("reputation", 0),
                "country_code": data.get("country_code"),
                "country_name": data.get("country_name"),
                "city": data.get("city"),
                "continent_code": data.get("continent_code"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "asn": data.get("asn"),
                "pulse_count": pulse_count,
                "pulses": pulses,
                "whois": data.get("whois"),
            }
            
            response.data = parsed_data
            
        except (KeyError, AttributeError) as e:
            response.status = ProviderStatus.ERROR
            response.error = f"Failed to parse OTX response: {str(e)}"
        
        return response
    
    def lookup_domain(self, domain: str) -> ProviderResponse:
        """
        Lookup domain reputation
        
        Args:
            domain: Domain name to lookup
            
        Returns:
            ProviderResponse with domain threat intelligence
        """
        url = f"{self.BASE_URL}/indicators/domain/{domain}/general"
        response = self._make_request("GET", url)
        
        if not response.is_success():
            return response
        
        try:
            data = response.data
            
            # Get URL list
            url_list_url = f"{self.BASE_URL}/indicators/domain/{domain}/url_list"
            url_response = self._make_request("GET", url_list_url)
            
            url_count = 0
            if url_response.is_success():
                url_count = url_response.data.get("url_list", [])
                url_count = len(url_count) if isinstance(url_count, list) else 0
            
            parsed_data = {
                "domain": domain,
                "alexa": data.get("alexa"),
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "whois": data.get("whois"),
                "url_count": url_count,
            }
            
            response.data = parsed_data
            
        except (KeyError, AttributeError) as e:
            response.status = ProviderStatus.ERROR
            response.error = f"Failed to parse OTX response: {str(e)}"
        
        return response
    
    def lookup_hash(self, file_hash: str) -> ProviderResponse:
        """
        Lookup file hash
        
        Args:
            file_hash: File hash (MD5, SHA1, SHA256)
            
        Returns:
            ProviderResponse with file threat intelligence
        """
        url = f"{self.BASE_URL}/indicators/file/{file_hash}/general"
        response = self._make_request("GET", url)
        
        if not response.is_success():
            return response
        
        try:
            data = response.data
            
            # Get analysis data
            analysis_url = f"{self.BASE_URL}/indicators/file/{file_hash}/analysis"
            analysis_response = self._make_request("GET", analysis_url)
            
            analysis_data = {}
            if analysis_response.is_success():
                analysis = analysis_response.data.get("analysis", {})
                plugins = analysis.get("plugins", {})
                
                # Extract key analysis info
                if "cuckoo" in plugins:
                    cuckoo = plugins["cuckoo"].get("result", {})
                    analysis_data["malware_families"] = cuckoo.get("malfamily", [])
                    analysis_data["score"] = cuckoo.get("score")
            
            parsed_data = {
                "hash": file_hash,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "file_type": data.get("file_type"),
                "file_class": data.get("file_class"),
                **analysis_data,
            }
            
            response.data = parsed_data
            
        except (KeyError, AttributeError) as e:
            response.status = ProviderStatus.ERROR
            response.error = f"Failed to parse OTX response: {str(e)}"
        
        return response
    
    def lookup_url(self, url: str) -> ProviderResponse:
        """
        Lookup URL reputation
        
        Args:
            url: URL to lookup
            
        Returns:
            ProviderResponse with URL threat intelligence
        """
        # URL needs to be properly encoded
        import urllib.parse
        encoded_url = urllib.parse.quote(url, safe='')
        
        lookup_url = f"{self.BASE_URL}/indicators/url/{encoded_url}/general"
        response = self._make_request("GET", lookup_url)
        
        if not response.is_success():
            return response
        
        try:
            data = response.data
            
            parsed_data = {
                "url": url,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "alexa": data.get("alexa"),
                "domain": data.get("domain"),
            }
            
            response.data = parsed_data
            
        except (KeyError, AttributeError) as e:
            response.status = ProviderStatus.ERROR
            response.error = f"Failed to parse OTX response: {str(e)}"
        
        return response
