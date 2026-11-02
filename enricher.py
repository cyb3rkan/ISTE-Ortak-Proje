"""
Main IOC Enricher orchestrator
Coordinates providers, analysis, and reporting
"""
import time
from typing import Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import Config
from .validators import IOCValidator, IOCType, sanitize_ioc
from .providers import (
    VirusTotalProvider,
    AbuseIPDBProvider,
    ShodanProvider,
    OTXProvider,
)
from .analyzer import AIAnalyzer, ThreatAnalysis
from .reporter import Reporter


class IOCEnricher:
    """Main IOC enrichment orchestrator"""
    
    def __init__(self):
        """Initialize enricher with all providers"""
        # Validate configuration
        errors = Config.validate()
        if errors:
            raise ValueError(f"Configuration errors: {', '.join(errors)}")
        
        # Initialize providers
        self.providers = {}
        
        if Config.VIRUSTOTAL_API_KEY:
            self.providers["VirusTotal"] = VirusTotalProvider(Config.VIRUSTOTAL_API_KEY)
        
        if Config.ABUSEIPDB_API_KEY:
            self.providers["AbuseIPDB"] = AbuseIPDBProvider(Config.ABUSEIPDB_API_KEY)
        
        if Config.SHODAN_API_KEY:
            self.providers["Shodan"] = ShodanProvider(Config.SHODAN_API_KEY)
        
        if Config.OTX_API_KEY:
            self.providers["AlienVault OTX"] = OTXProvider(Config.OTX_API_KEY)
        
        # Initialize AI analyzer
        self.ai_analyzer = AIAnalyzer()
        
        # Initialize reporter
        self.reporter = Reporter()
    
    def enrich(
        self,
        ioc: str,
        output_format: str = "terminal",
        save_report: bool = False,
    ) -> Dict[str, Any]:
        """
        Enrich IOC with threat intelligence
        
        Args:
            ioc: Indicator of Compromise to analyze
            output_format: Output format (terminal, json, markdown)
            save_report: Whether to save report to file
            
        Returns:
            Dictionary containing all results
        """
        start_time = time.time()
        
        # Sanitize and validate IOC
        ioc = sanitize_ioc(ioc)
        is_valid, ioc_type, error = IOCValidator.validate(ioc)
        
        if not is_valid:
            return {
                "success": False,
                "error": error,
                "ioc": ioc,
            }
        
        print(f"\n🔍 Analyzing {ioc_type.value.upper()}: {ioc}")
        print(f"📡 Querying {len(self.providers)} threat intelligence providers...\n")
        
        # Query all providers in parallel
        provider_results = self._query_providers(ioc, ioc_type)
        
        # AI analysis
        print("🤖 Performing AI analysis...")
        ai_analysis = self.ai_analyzer.analyze(ioc, ioc_type, provider_results)
        
        # Generate report
        report_content = self._generate_report(
            ioc, ioc_type, provider_results, ai_analysis, output_format
        )
        
        # Save report if requested
        report_path = None
        if save_report and output_format != "terminal":
            ext = "json" if output_format == "json" else "md"
            report_path = self.reporter.save_report(
                report_content,
                f"ioc_report_{ioc_type.value}",
                ext,
            )
        
        execution_time = time.time() - start_time
        
        # Print report to terminal
        if output_format == "terminal":
            print(report_content)
        
        return {
            "success": True,
            "ioc": ioc,
            "ioc_type": ioc_type.value,
            "provider_results": provider_results,
            "ai_analysis": {
                "risk_score": ai_analysis.risk_score,
                "severity": ai_analysis.severity,
                "summary_tr": ai_analysis.summary_tr,
                "summary_en": ai_analysis.summary_en,
                "key_findings": ai_analysis.key_findings,
                "recommendations": ai_analysis.recommendations,
                "tags": ai_analysis.tags,
                "confidence": ai_analysis.confidence,
            },
            "report": report_content if output_format != "terminal" else None,
            "report_path": str(report_path) if report_path else None,
            "execution_time": round(execution_time, 2),
        }
    
    def _query_providers(self, ioc: str, ioc_type: IOCType) -> Dict[str, Any]:
        """
        Query all applicable providers in parallel
        
        Args:
            ioc: The indicator to query
            ioc_type: Type of indicator
            
        Returns:
            Dictionary of provider results
        """
        results = {}
        
        # Determine which providers support this IOC type
        provider_methods = self._get_provider_methods(ioc_type)
        
        # Query providers in parallel
        with ThreadPoolExecutor(max_workers=Config.MAX_CONCURRENT_REQUESTS) as executor:
            future_to_provider = {}
            
            for provider_name, method_name in provider_methods.items():
                if provider_name in self.providers:
                    provider = self.providers[provider_name]
                    method = getattr(provider, method_name)
                    future = executor.submit(method, ioc)
                    future_to_provider[future] = provider_name
            
            # Collect results
            for future in as_completed(future_to_provider):
                provider_name = future_to_provider[future]
                try:
                    result = future.result()
                    results[provider_name] = result.to_dict()
                    
                    # Print progress
                    status_icon = "✓" if result.is_success() else "✗"
                    print(f"  {status_icon} {provider_name}: {result.status.value}")
                    
                except Exception as e:
                    results[provider_name] = {
                        "provider": provider_name,
                        "status": "error",
                        "error": str(e),
                    }
                    print(f"  ✗ {provider_name}: error - {str(e)}")
        
        print()  # Empty line after provider queries
        return results
    
    def _get_provider_methods(self, ioc_type: IOCType) -> Dict[str, str]:
        """
        Get provider methods based on IOC type
        
        Returns:
            Dictionary mapping provider names to method names
        """
        if ioc_type in [IOCType.IPV4, IOCType.IPV6]:
            return {
                "VirusTotal": "lookup_ip",
                "AbuseIPDB": "lookup_ip",
                "Shodan": "lookup_ip",
                "AlienVault OTX": "lookup_ip",
            }
        
        elif ioc_type == IOCType.DOMAIN:
            return {
                "VirusTotal": "lookup_domain",
                "Shodan": "lookup_domain",
                "AlienVault OTX": "lookup_domain",
            }
        
        elif ioc_type in [IOCType.MD5, IOCType.SHA1, IOCType.SHA256]:
            return {
                "VirusTotal": "lookup_hash",
                "AlienVault OTX": "lookup_hash",
            }
        
        elif ioc_type == IOCType.URL:
            return {
                "VirusTotal": "lookup_url",
                "AlienVault OTX": "lookup_url",
            }
        
        else:
            return {}
    
    def _generate_report(
        self,
        ioc: str,
        ioc_type: IOCType,
        provider_results: Dict[str, Any],
        ai_analysis: ThreatAnalysis,
        output_format: str,
    ) -> str:
        """Generate report in specified format"""
        if output_format == "json":
            return self.reporter.generate_json_report(
                ioc, ioc_type, provider_results, ai_analysis
            )
        elif output_format == "markdown":
            return self.reporter.generate_markdown_report(
                ioc, ioc_type, provider_results, ai_analysis
            )
        else:  # terminal
            return self.reporter.generate_terminal_report(
                ioc, ioc_type, provider_results, ai_analysis
            )
    
    def enrich_batch(
        self,
        iocs: List[str],
        output_format: str = "json",
        save_reports: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Enrich multiple IOCs in batch (parallel execution)

        Args:
            iocs: List of IOCs to analyze
            output_format: Output format for reports
            save_reports: Whether to save individual reports

        Returns:
            List of results for each IOC, in the same order as input
        """
        total = len(iocs)
        results: List[Dict[str, Any]] = [{}] * total

        print(f"\n🔄 Batch processing {total} IOCs...\n")

        with ThreadPoolExecutor(max_workers=Config.MAX_CONCURRENT_REQUESTS) as executor:
            future_to_index = {
                executor.submit(self.enrich, ioc, output_format, save_reports): i
                for i, ioc in enumerate(iocs)
            }
            for future in as_completed(future_to_index):
                idx = future_to_index[future]
                ioc = iocs[idx]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = {"success": False, "ioc": ioc, "error": str(e)}
                print(f"  [{idx + 1}/{total}] Done: {ioc}")

        print(f"\n✅ Batch processing complete! {total} IOCs analyzed.\n")

        return results
    
    def get_provider_status(self) -> Dict[str, bool]:
        """Get status of all providers"""
        return {
            name: name in self.providers
            for name in ["VirusTotal", "AbuseIPDB", "Shodan", "AlienVault OTX"]
        }
