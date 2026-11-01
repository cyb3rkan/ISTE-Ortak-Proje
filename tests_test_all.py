#!/usr/bin/env python3
"""
IOC Enricher Agent - Comprehensive Test Suite
Tests all features and providers with detailed error diagnosis
"""
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.config import Config
from src.validators import IOCValidator, IOCType, sanitize_ioc
from src.enricher import IOCEnricher


class TestRunner:
    """Run comprehensive tests"""
    
    def __init__(self):
        self.tests_passed = 0
        self.tests_failed = 0
        self.test_results = []
        
    def print_header(self, text):
        """Print section header"""
        print(f"\n{'='*70}")
        print(f"  {text}")
        print(f"{'='*70}\n")
    
    def print_test(self, name, status, message=""):
        """Print test result"""
        icon = "✅" if status else "❌"
        result = "PASS" if status else "FAIL"
        print(f"{icon} [{result}] {name}")
        if message:
            # Split long messages
            if len(message) > 70:
                print(f"    └─ {message[:70]}...")
            else:
                print(f"    └─ {message}")
        
        if status:
            self.tests_passed += 1
        else:
            self.tests_failed += 1
        
        self.test_results.append({
            "name": name,
            "status": status,
            "message": message
        })
    
    def diagnose_error(self, error_msg: str) -> str:
        """Diagnose common errors and provide helpful messages"""
        error_lower = error_msg.lower()
        
        # Connection errors
        if "connection" in error_lower and "aborted" in error_lower:
            return "Network issue - Windows firewall or ISP blocking connection"
        
        if "max retries exceeded" in error_lower:
            return "Connection timeout - Network/firewall issue"
        
        if "protocolerror" in error_lower:
            return "Network protocol error - TLS/SSL compatibility issue"
        
        # API errors
        if "429" in error_msg or "quota" in error_lower:
            return "API quota exceeded - Daily/hourly limit reached"
        
        if "401" in error_msg or "unauthorized" in error_lower:
            return "Invalid API key - Check your configuration"
        
        if "403" in error_msg or "forbidden" in error_lower:
            return "Access forbidden - API key may lack permissions"
        
        if "404" in error_msg:
            return "Resource not found - IOC not in database or endpoint issue"
        
        if "500" in error_msg or "502" in error_msg or "503" in error_msg:
            return "Provider server error - Try again later"
        
        # Timeout errors
        if "timeout" in error_lower:
            return "Request timeout - Provider slow or network issue"
        
        # SSL/TLS errors
        if "ssl" in error_lower or "certificate" in error_lower:
            return "SSL/TLS error - Certificate or encryption issue"
        
        # DNS errors
        if "dns" in error_lower or "name resolution" in error_lower:
            return "DNS resolution failed - Check internet connection"
        
        # Default
        return "Unknown error - Check logs for details"
    
    def test_1_environment(self):
        """Test 1: Environment Configuration"""
        self.print_header("TEST 1: Environment & Configuration")
        
        # Test API keys
        tests = {
            "VirusTotal API Key": bool(Config.VIRUSTOTAL_API_KEY),
            "AbuseIPDB API Key": bool(Config.ABUSEIPDB_API_KEY),
            "Shodan API Key": bool(Config.SHODAN_API_KEY),
            "OTX API Key": bool(Config.OTX_API_KEY),
        }
        
        # Test AI provider
        if Config.AI_PROVIDER == "openai":
            tests["OpenAI API Key"] = bool(Config.OPENAI_API_KEY)
        elif Config.AI_PROVIDER == "gemini":
            tests["Gemini API Key"] = bool(Config.GEMINI_API_KEY)
        
        for name, result in tests.items():
            self.print_test(name, result, "Configured" if result else "Missing")
        
        # Test AI Provider Selection
        ai_provider_valid = Config.AI_PROVIDER in ["openai", "gemini"]
        self.print_test(
            "AI Provider Selection", 
            ai_provider_valid,
            f"Using: {Config.AI_PROVIDER.upper()}"
        )
        
        # Test directories
        dirs_exist = all([
            Config.DATA_DIR.exists(),
            Config.CACHE_DIR.exists(),
            Config.REPORTS_DIR.exists(),
            Config.LOGS_DIR.exists(),
        ])
        self.print_test("Required Directories", dirs_exist)
    
    def test_2_validators(self):
        """Test 2: IOC Validators"""
        self.print_header("TEST 2: IOC Validation")
        
        test_cases = [
            ("8.8.8.8", IOCType.IPV4, True),
            ("2001:4860:4860::8888", IOCType.IPV6, True),
            ("google.com", IOCType.DOMAIN, True),
            ("http://example.com", IOCType.URL, True),
            ("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5, True),
            ("356a192b7913b04c54574d18c28d46e6395428ab", IOCType.SHA1, True),
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCType.SHA256, True),
            ("user@example.com", IOCType.EMAIL, True),
            ("invalid_ioc_12345", IOCType.UNKNOWN, False),
        ]
        
        for ioc, expected_type, should_pass in test_cases:
            detected_type = IOCValidator.identify_ioc_type(ioc)
            is_valid, _, _ = IOCValidator.validate(ioc)
            
            passed = (detected_type == expected_type) and (is_valid == should_pass)
            self.print_test(
                f"Validate: {ioc[:30]}...", 
                passed,
                f"Type: {detected_type.value}"
            )
        
        # Test sanitization
        defanged = "hxxp://example[.]com"
        sanitized = sanitize_ioc(defanged)
        sanitize_works = sanitized == "http://example.com"
        self.print_test(
            "IOC Sanitization (Defanging)", 
            sanitize_works,
            f"{defanged} → {sanitized}"
        )
    
    def test_3_providers(self):
        """Test 3: Threat Intelligence Providers"""
        self.print_header("TEST 3: Provider Connectivity")
        
        try:
            enricher = IOCEnricher()
            
            # Test with a safe IP (Google DNS)
            test_ip = "8.8.8.8"
            print(f"Testing with IP: {test_ip}\n")
            
            # Get provider results
            from src.validators import IOCType
            provider_results = enricher._query_providers(test_ip, IOCType.IPV4)
            
            # Check each provider
            for provider_name, result in provider_results.items():
                status = result.get("status")
                passed = status in ["success", "not_found"]
                
                if status == "success":
                    msg = f"✅ Response time: {result.get('response_time', 0):.2f}s"
                elif status == "not_found":
                    msg = "ℹ️  Not in database (this is OK)"
                else:
                    error_msg = result.get("error", "Unknown error")
                    diagnosis = self.diagnose_error(error_msg)
                    msg = f"⚠️  {diagnosis}"
                
                self.print_test(f"{provider_name} Connectivity", passed, msg)
                
        except Exception as e:
            self.print_test("Provider Initialization", False, str(e))
    
    def test_4_ai_analysis(self):
        """Test 4: AI Analysis"""
        self.print_header("TEST 4: AI Analysis Engine")
        
        try:
            from src.analyzer import AIAnalyzer
            
            analyzer = AIAnalyzer()
            
            # Test with mock data
            mock_provider_results = {
                "VirusTotal": {
                    "status": "success",
                    "data": {
                        "malicious_count": 0,
                        "total_engines": 93
                    }
                }
            }
            
            self.print_test(
                f"AI Provider: {Config.AI_PROVIDER.upper()}", 
                True,
                "Initialized successfully"
            )
            
            # Try to analyze
            result = analyzer.analyze(
                "8.8.8.8",
                IOCType.IPV4,
                mock_provider_results
            )
            
            # Check if using fallback
            is_fallback = "fallback" in str(result.tags).lower()
            if is_fallback:
                print("    ⚠️  Note: AI using fallback (API quota may be exceeded)")
            
            # Check analysis components
            self.print_test("Risk Score Generation", 0 <= result.risk_score <= 100)
            self.print_test("Severity Classification", result.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            self.print_test("Summary Generation (TR)", bool(result.summary_tr))
            self.print_test("Summary Generation (EN)", bool(result.summary_en))
            self.print_test("Recommendations Generation", len(result.recommendations) > 0)
            
        except Exception as e:
            diagnosis = self.diagnose_error(str(e))
            self.print_test("AI Analysis Engine", False, diagnosis)
    
    def test_5_reporting(self):
        """Test 5: Report Generation"""
        self.print_header("TEST 5: Report Generation")
        
        try:
            from src.reporter import Reporter
            from src.analyzer import ThreatAnalysis
            
            # Create mock analysis
            mock_analysis = ThreatAnalysis(
                risk_score=25,
                severity="LOW",
                summary_tr="Test özeti",
                summary_en="Test summary",
                key_findings=["Finding 1", "Finding 2"],
                recommendations=["Recommendation 1"],
                tags=["test", "mock"],
                confidence=0.95
            )
            
            mock_provider_results = {
                "VirusTotal": {"status": "success", "data": {"malicious_count": 0}}
            }
            
            reporter = Reporter()
            
            # Test terminal report
            terminal_report = reporter.generate_terminal_report(
                "8.8.8.8",
                IOCType.IPV4,
                mock_provider_results,
                mock_analysis
            )
            self.print_test("Terminal Report Generation", len(terminal_report) > 0)
            
            # Test JSON report
            json_report = reporter.generate_json_report(
                "8.8.8.8",
                IOCType.IPV4,
                mock_provider_results,
                mock_analysis
            )
            self.print_test("JSON Report Generation", "risk_score" in json_report)
            
            # Test Markdown report
            md_report = reporter.generate_markdown_report(
                "8.8.8.8",
                IOCType.IPV4,
                mock_provider_results,
                mock_analysis
            )
            self.print_test("Markdown Report Generation", "# 🔍 IOC" in md_report)
            
        except Exception as e:
            self.print_test("Report Generation", False, str(e))
    
    def test_6_full_enrichment(self):
        """Test 6: Full Enrichment Flow"""
        self.print_header("TEST 6: Full IOC Enrichment Flow")
        
        try:
            enricher = IOCEnricher()
            
            # Test different IOC types
            test_iocs = [
                ("8.8.8.8", "Safe IP"),
                ("google.com", "Safe Domain"),
                ("44d88612fea8a8f36de82e1278abb02f", "Test Hash"),
            ]
            
            for ioc, description in test_iocs:
                print(f"\n  Testing: {description} ({ioc})")
                
                result = enricher.enrich(ioc, output_format="json", save_report=False)
                
                passed = result.get("success", False)
                exec_time = result.get("execution_time", 0)
                
                self.print_test(
                    f"Enrich {description}",
                    passed,
                    f"Completed in {exec_time:.1f}s"
                )
                
                if passed:
                    # Check result components
                    has_providers = len(result.get("provider_results", {})) > 0
                    has_analysis = result.get("ai_analysis") is not None
                    
                    self.print_test(
                        f"  └─ Provider Results",
                        has_providers,
                        f"{len(result.get('provider_results', {}))} providers"
                    )
                    
                    self.print_test(
                        f"  └─ AI Analysis",
                        has_analysis,
                        f"Risk: {result['ai_analysis'].get('risk_score', 'N/A')}/100"
                    )
                
        except Exception as e:
            self.print_test("Full Enrichment Flow", False, str(e))
    
    def test_7_batch_processing(self):
        """Test 7: Batch Processing"""
        self.print_header("TEST 7: Batch Processing")
        
        try:
            enricher = IOCEnricher()
            
            # Test batch with multiple IOCs
            test_batch = ["8.8.8.8", "1.1.1.1", "google.com"]
            
            print(f"  Processing {len(test_batch)} IOCs in batch...\n")
            
            results = enricher.enrich_batch(
                test_batch,
                output_format="json",
                save_reports=False
            )
            
            success_count = sum(1 for r in results if r.get("success"))
            
            self.print_test(
                "Batch Processing",
                success_count == len(test_batch),
                f"{success_count}/{len(test_batch)} IOCs processed"
            )
            
        except Exception as e:
            self.print_test("Batch Processing", False, str(e))
    
    def test_8_error_handling(self):
        """Test 8: Error Handling"""
        self.print_header("TEST 8: Error Handling")
        
        try:
            enricher = IOCEnricher()
            
            # Test invalid IOC
            result = enricher.enrich("invalid_ioc_xyz_123", output_format="json")
            
            invalid_handled = not result.get("success") and "error" in result
            self.print_test(
                "Invalid IOC Handling",
                invalid_handled,
                result.get("error", "")[:50]
            )
            
            # Test empty IOC
            result = enricher.enrich("", output_format="json")
            empty_handled = not result.get("success")
            self.print_test("Empty IOC Handling", empty_handled)
            
        except Exception as e:
            self.print_test("Error Handling", False, str(e))
    
    def run_all_tests(self):
        """Run all tests"""
        print("\n" + "="*70)
        print("  IOC ENRICHER AGENT - COMPREHENSIVE TEST SUITE")
        print("="*70)
        
        start_time = time.time()
        
        # Run all test suites
        self.test_1_environment()
        self.test_2_validators()
        self.test_3_providers()
        self.test_4_ai_analysis()
        self.test_5_reporting()
        self.test_6_full_enrichment()
        self.test_7_batch_processing()
        self.test_8_error_handling()
        
        # Print summary
        self.print_summary(time.time() - start_time)
    
    def print_summary(self, total_time):
        """Print test summary"""
        self.print_header("TEST SUMMARY")
        
        total_tests = self.tests_passed + self.tests_failed
        pass_rate = (self.tests_passed / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Total Tests:    {total_tests}")
        print(f"Passed:         {self.tests_passed} ✅")
        print(f"Failed:         {self.tests_failed} ❌")
        print(f"Pass Rate:      {pass_rate:.1f}%")
        print(f"Execution Time: {total_time:.2f}s")
        
        if self.tests_failed > 0:
            print("\n⚠️  FAILED TESTS:")
            for result in self.test_results:
                if not result["status"]:
                    print(f"  ❌ {result['name']}")
                    if result["message"]:
                        print(f"     └─ {result['message']}")
        
        print("\n" + "="*70)
        
        if pass_rate >= 90:
            print("  🎉 EXCELLENT! All critical features working!")
        elif pass_rate >= 70:
            print("  ✅ GOOD! Most features working, minor issues.")
        elif pass_rate >= 50:
            print("  ⚠️  WARNING! Several features need attention.")
        else:
            print("  ❌ CRITICAL! Major issues detected.")
        
        print("="*70 + "\n")
        
        # Print helpful notes
        if self.tests_failed > 0:
            print("💡 TROUBLESHOOTING TIPS:")
            print("   • Connection errors: Check firewall/antivirus settings")
            print("   • API quota errors: Wait 24h or get new API key")
            print("   • SSL errors: Update Python or run: pip install --upgrade certifi")
            print()
        
        return self.tests_failed == 0


def main():
    """Main test runner"""
    try:
        runner = TestRunner()
        success = runner.run_all_tests()
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests cancelled by user")
        return 130
        
    except Exception as e:
        print(f"\n❌ Fatal test error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
