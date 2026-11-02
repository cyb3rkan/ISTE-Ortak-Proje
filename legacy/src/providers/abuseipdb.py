"""
AbuseIPDB API Provider
https://docs.abuseipdb.com/
"""
from typing import Dict
from .base import BaseProvider, ProviderResponse, ProviderStatus


class AbuseIPDBProvider(BaseProvider):
    """AbuseIPDB IP reputation provider"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str, timeout: int = 60):
        """Initialize with longer timeout for AbuseIPDB (Turkey connection issues)"""
        super().__init__(api_key, timeout)
    
    @property
    def name(self) -> str:
        return "AbuseIPDB"
    
    def _get_headers(self) -> Dict[str, str]:
        """Get AbuseIPDB API headers"""
        return {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "IOC-Enricher-Agent/1.0",
        }
    
    def lookup_ip(self, ip: str) -> ProviderResponse:
        """
        Lookup IP address reputation
        
        Args:
            ip: IP address to check
            
        Returns:
            ProviderResponse with IP reputation data
        """
        url = f"{self.BASE_URL}/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,  # Check reports from last 90 days
            "verbose": True,
        }
        
        response = self._make_request("GET", url, params=params)
        
        if not response.is_success():
            return response
        
        try:
            data = response.data.get("data", {})
            
            parsed_data = {
                "ip": ip,
                "is_whitelisted": data.get("isWhitelisted", False),
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code": data.get("countryCode"),
                "country_name": data.get("countryName"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "is_public": data.get("isPublic", True),
                "is_tor": data.get("isTor", False),
                "hostnames": data.get("hostnames", []),
            }
            
            # Get recent reports if available
            reports = data.get("reports", [])
            if reports:
                parsed_data["recent_reports"] = [
                    {
                        "reported_at": r.get("reportedAt"),
                        "comment": r.get("comment", "")[:200],  # Limit comment length
                        "categories": r.get("categories", []),
                        "reporter_country": r.get("reporterCountryCode"),
                    }
                    for r in reports[:5]  # Only keep 5 most recent
                ]
            
            response.data = parsed_data
            
        except (KeyError, AttributeError) as e:
            response.status = ProviderStatus.ERROR
            response.error = f"Failed to parse AbuseIPDB response: {str(e)}"
        
        return response
    
    def lookup_domain(self, domain: str) -> ProviderResponse:
        """
        AbuseIPDB doesn't support domain lookup
        """
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.ERROR,
            error="Domain lookup not supported by AbuseIPDB",
        )
    
    def lookup_hash(self, file_hash: str) -> ProviderResponse:
        """
        AbuseIPDB doesn't support hash lookup
        """
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.ERROR,
            error="Hash lookup not supported by AbuseIPDB",
        )
    
    def report_ip(self, ip: str, categories: list[int], comment: str = "") -> ProviderResponse:
        """
        Report an IP address (optional feature)
        
        Args:
            ip: IP address to report
            categories: List of abuse category IDs
            comment: Additional comment
            
        Returns:
            ProviderResponse
        """
        url = f"{self.BASE_URL}/report"
        data = {
            "ip": ip,
            "categories": ",".join(map(str, categories)),
            "comment": comment,
        }
        
        return self._make_request("POST", url, json_data=data)
