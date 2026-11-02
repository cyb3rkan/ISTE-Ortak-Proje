"""
Shodan API Provider
https://developer.shodan.io/api
"""
from typing import Dict
from .base import BaseProvider, ProviderResponse, ProviderStatus


class ShodanProvider(BaseProvider):
    """Shodan search engine provider"""
    
    BASE_URL = "https://api.shodan.io"
    
    @property
    def name(self) -> str:
        return "Shodan"
    
    def _get_headers(self) -> Dict[str, str]:
        """Get Shodan API headers"""
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

    def lookup_ip(self, ip: str) -> ProviderResponse:
        """
        Lookup IP address information

        Args:
            ip: IP address to lookup

        Returns:
            ProviderResponse with IP information
        """
        url = f"{self.BASE_URL}/shodan/host/{ip}"
        params = {}

        response = self._make_request("GET", url, params=params)
        
        if not response.is_success():
            # Shodan returns 404 if IP not found
            if response.status == ProviderStatus.ERROR and "404" in str(response.error):
                response.status = ProviderStatus.NOT_FOUND
                response.error = "IP not found in Shodan database"
            return response
        
        try:
            data = response.data
            
            # Extract port information
            ports = data.get("ports", [])
            services = []
            
            for service_data in data.get("data", []):
                services.append({
                    "port": service_data.get("port"),
                    "transport": service_data.get("transport"),
                    "product": service_data.get("product"),
                    "version": service_data.get("version"),
                    "banner": service_data.get("data", "")[:200],  # Limit banner length
                })
            
            parsed_data = {
                "ip": ip,
                "hostnames": data.get("hostnames", []),
                "domains": data.get("domains", []),
                "country_code": data.get("country_code"),
                "country_name": data.get("country_name"),
                "city": data.get("city"),
                "region_code": data.get("region_code"),
                "postal_code": data.get("postal_code"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "organization": data.get("org"),
                "os": data.get("os"),
                "ports": ports,
                "services": services,
                "tags": data.get("tags", []),
                "vulns": list(data.get("vulns", [])),  # CVE IDs
                "last_update": data.get("last_update"),
            }
            
            response.data = parsed_data
            
        except (KeyError, AttributeError) as e:
            response.status = ProviderStatus.ERROR
            response.error = f"Failed to parse Shodan response: {str(e)}"
        
        return response
    
    def lookup_domain(self, domain: str) -> ProviderResponse:
        """
        Lookup domain information via DNS resolve
        
        Args:
            domain: Domain name to lookup
            
        Returns:
            ProviderResponse with domain DNS information
        """
        url = f"{self.BASE_URL}/dns/resolve"
        params = {
            "hostnames": domain,
        }
        
        response = self._make_request("GET", url, params=params)
        
        if not response.is_success():
            return response
        
        try:
            data = response.data
            ip_address = data.get(domain)
            
            if not ip_address:
                response.status = ProviderStatus.NOT_FOUND
                response.error = "Domain not resolved"
                return response
            
            parsed_data = {
                "domain": domain,
                "ip_address": ip_address,
            }
            
            # Optionally lookup the resolved IP
            # ip_info = self.lookup_ip(ip_address)
            # if ip_info.is_success():
            #     parsed_data["ip_info"] = ip_info.data
            
            response.data = parsed_data
            
        except (KeyError, AttributeError) as e:
            response.status = ProviderStatus.ERROR
            response.error = f"Failed to parse Shodan response: {str(e)}"
        
        return response
    
    def lookup_hash(self, file_hash: str) -> ProviderResponse:
        """
        Shodan doesn't support hash lookup
        """
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.ERROR,
            error="Hash lookup not supported by Shodan",
        )
    
    def search(self, query: str, limit: int = 100) -> ProviderResponse:
        """
        Search Shodan (optional feature)
        
        Args:
            query: Shodan search query
            limit: Maximum number of results
            
        Returns:
            ProviderResponse with search results
        """
        url = f"{self.BASE_URL}/shodan/host/search"
        params = {
            "query": query,
            "limit": limit,
        }
        
        return self._make_request("GET", url, params=params)
