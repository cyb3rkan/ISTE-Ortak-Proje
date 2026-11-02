"""
AI-Powered Threat Analysis using OpenAI or Google Gemini
"""
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from openai import OpenAI

try:
    import google.generativeai as genai
    GENAI_VERSION = "current"
except ImportError:
    genai = None
    GENAI_VERSION = None

from .config import Config
from .validators import IOCType


@dataclass
class ThreatAnalysis:
    """AI-generated threat analysis"""
    risk_score: int  # 0-100
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    summary_tr: str  # Turkish summary
    summary_en: str  # English summary
    key_findings: List[str]
    recommendations: List[str]
    tags: List[str]
    confidence: float  # 0.0-1.0
    

class AIAnalyzer:
    """AI-powered threat analyzer using OpenAI or Google Gemini"""
    
    SEVERITY_THRESHOLDS = {
        "LOW": (0, 25),
        "MEDIUM": (25, 50),
        "HIGH": (50, 75),
        "CRITICAL": (75, 100),
    }
    
    def __init__(self, api_key: Optional[str] = None, provider: Optional[str] = None):
        """
        Initialize AI analyzer
        
        Args:
            api_key: API key (uses Config if not provided)
            provider: AI provider ("openai" or "gemini", uses Config if not provided)
        """
        self.provider = provider or Config.AI_PROVIDER
        
        if self.provider == "openai":
            self.api_key = api_key or Config.OPENAI_API_KEY
            # Fix for Python 3.13 and newer OpenAI versions
            try:
                self.client = OpenAI(api_key=self.api_key)
            except TypeError:
                # Fallback for compatibility issues
                import httpx
                self.client = OpenAI(
                    api_key=self.api_key,
                    http_client=httpx.Client()
                )
            self.model = Config.OPENAI_MODEL
            self.max_tokens = Config.OPENAI_MAX_TOKENS
            self.temperature = Config.OPENAI_TEMPERATURE
            
        elif self.provider == "gemini":
            if genai is None:
                raise ImportError("Gemini SDK not installed. Run: pip install google-generativeai")
            
            self.api_key = api_key or Config.GEMINI_API_KEY
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(Config.GEMINI_MODEL)
            self.max_tokens = Config.GEMINI_MAX_TOKENS
            self.temperature = Config.GEMINI_TEMPERATURE
            
        else:
            raise ValueError(f"Unsupported AI provider: {self.provider}")
    
    def analyze(
        self,
        ioc: str,
        ioc_type: IOCType,
        provider_results: Dict[str, Any],
    ) -> ThreatAnalysis:
        """
        Analyze IOC using AI
        
        Args:
            ioc: The indicator being analyzed
            ioc_type: Type of IOC
            provider_results: Results from all providers
            
        Returns:
            ThreatAnalysis object
        """
        # Prepare context for AI
        context = self._prepare_context(ioc, ioc_type, provider_results)
        
        # Get AI analysis
        prompt = self._build_prompt(ioc, ioc_type, context)
        
        try:
            if self.provider == "openai":
                analysis_text = self._call_openai(prompt)
            elif self.provider == "gemini":
                analysis_text = self._call_gemini(prompt)
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
            
            # Parse AI response
            return self._parse_analysis(analysis_text, provider_results, ioc_type)
            
        except Exception as e:
            # Fallback to rule-based analysis if AI fails
            return self._fallback_analysis(ioc, ioc_type, provider_results, str(e))
    
    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API with retry"""
        import time
        max_retries = 2
        last_error = None
        
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": self._get_system_prompt(),
                        },
                        {
                            "role": "user",
                            "content": prompt,
                        }
                    ],
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    timeout=30.0  # 30 second timeout
                )
                return response.choices[0].message.content
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    time.sleep(2)  # Wait 2 seconds before retry
                    continue
        
        # If all retries fail, raise the last error
        raise last_error

    def _call_gemini(self, prompt: str) -> str:
        """Call Google Gemini API"""
        full_prompt = f"{self._get_system_prompt()}\n\n{prompt}"
        
        generation_config = genai.types.GenerationConfig(
            temperature=self.temperature,
            max_output_tokens=self.max_tokens,
        )
        
        response = self.model.generate_content(
            full_prompt,
            generation_config=generation_config
        )
        
        return response.text
    
    def _get_system_prompt(self) -> str:
        """Get system prompt for AI"""
        return """Sen bir siber güvenlik uzmanısın ve tehdit istihbaratı analizi yapıyorsun.
Görevin, verilen IOC (Indicator of Compromise) hakkında kapsamlı bir analiz yapmak.

Analiz formatı (MUTLAKA bu formatta cevap ver):
RISK_SCORE: [0-100 arası sayı]
SUMMARY_TR: [Türkçe özet, 2-3 cümle]
SUMMARY_EN: [English summary, 2-3 sentences]
KEY_FINDINGS:
- [Önemli bulgu 1]
- [Önemli bulgu 2]
- [Önemli bulgu 3]
RECOMMENDATIONS:
- [Öneri 1]
- [Öneri 2]
- [Öneri 3]
TAGS: [tag1, tag2, tag3]

Kurallar:
1. Risk skoru objektif verilere dayanmalı
2. Özet net ve anlaşılır olmalı
3. Bulgular spesifik olmalı
4. Öneriler MUTLAKA uygulanabilir olmalı (en az 2 öneri)
5. Tag'ler kısa ve açıklayıcı olmalı
6. RECOMMENDATIONS kısmını asla boş bırakma!"""
    
    def _prepare_context(
        self,
        ioc: str,
        ioc_type: IOCType,
        provider_results: Dict[str, Any],
    ) -> str:
        """Prepare context from provider results"""
        context_parts = []
        
        # VirusTotal
        if "VirusTotal" in provider_results:
            vt = provider_results["VirusTotal"]
            if vt.get("status") == "success" and vt.get("data"):
                data = vt["data"]
                malicious = data.get("malicious_count", 0)
                total = data.get("total_engines", 0)
                context_parts.append(
                    f"VirusTotal: {malicious}/{total} motor kötü amaçlı olarak işaretledi"
                )
        
        # AbuseIPDB
        if "AbuseIPDB" in provider_results:
            abuse = provider_results["AbuseIPDB"]
            if abuse.get("status") == "success" and abuse.get("data"):
                data = abuse["data"]
                score = data.get("abuse_confidence_score", 0)
                reports = data.get("total_reports", 0)
                context_parts.append(
                    f"AbuseIPDB: %{score} güven skoru, {reports} rapor"
                )
        
        # Shodan
        if "Shodan" in provider_results:
            shodan = provider_results["Shodan"]
            if shodan.get("status") == "success" and shodan.get("data"):
                data = shodan["data"]
                ports = data.get("ports", [])
                vulns = data.get("vulns", [])
                if ports:
                    context_parts.append(f"Shodan: Açık portlar {ports}")
                if vulns:
                    context_parts.append(f"Shodan: Güvenlik açıkları {vulns[:5]}")
        
        # OTX
        if "AlienVault OTX" in provider_results:
            otx = provider_results["AlienVault OTX"]
            if otx.get("status") == "success" and otx.get("data"):
                data = otx["data"]
                pulses = data.get("pulse_count", 0)
                if pulses > 0:
                    context_parts.append(f"OTX: {pulses} threat pulse")
        
        return "\n".join(context_parts) if context_parts else "Yeterli veri yok"
    
    def _build_prompt(self, ioc: str, ioc_type: IOCType, context: str) -> str:
        """Build prompt for AI"""
        import json
        ioc_data = json.dumps({"ioc": ioc, "type": ioc_type.value}, ensure_ascii=False)
        return f"""IOC Analizi İsteği:

[IOC_DATA]
{ioc_data}
[/IOC_DATA]

Threat Intelligence Verileri:
{context}

Yukarıdaki [IOC_DATA] bloğundaki gösterge hakkında kapsamlı bir güvenlik analizi yap ve MUTLAKA yukarıdaki format ile cevap ver."""

    def _parse_analysis(self, analysis_text: str, provider_results: Dict, ioc_type: IOCType) -> ThreatAnalysis:
        """Parse AI response into ThreatAnalysis object"""
        lines = analysis_text.strip().split('\n')

        risk_score = 50  # default
        summary_tr = ""
        summary_en = ""
        key_findings = []
        recommendations = []
        tags = []

        current_section = None

        for line in lines:
            line = line.strip()

            if line.startswith("RISK_SCORE:"):
                try:
                    score_text = line.split(":", 1)[1].strip()
                    # Extract just the number (handle "50/100" or "50" formats)
                    score_text = score_text.split()[0].split('/')[0]
                    risk_score = int(score_text)
                    risk_score = max(0, min(100, risk_score))
                except (ValueError, IndexError):
                    pass

            elif line.startswith("SUMMARY_TR:"):
                summary_tr = line.split(":", 1)[1].strip()
                current_section = "summary_tr"

            elif line.startswith("SUMMARY_EN:"):
                summary_en = line.split(":", 1)[1].strip()
                current_section = "summary_en"

            elif line.startswith("KEY_FINDINGS:"):
                current_section = "findings"

            elif line.startswith("RECOMMENDATIONS:"):
                current_section = "recommendations"

            elif line.startswith("TAGS:"):
                tags_text = line.split(":", 1)[1].strip()
                tags = [t.strip() for t in tags_text.replace("[", "").replace("]", "").split(",") if t.strip()]
                current_section = None

            elif line.startswith("-") and current_section:
                content = line[1:].strip()
                if content:  # Only add non-empty content
                    if current_section == "findings":
                        key_findings.append(content)
                    elif current_section == "recommendations":
                        recommendations.append(content)

            elif current_section in ["summary_tr", "summary_en"] and line and not line.startswith("KEY_FINDINGS") and not line.startswith("RECOMMENDATIONS"):
                if current_section == "summary_tr":
                    summary_tr += " " + line
                else:
                    summary_en += " " + line

        # Fallback: Eğer AI hiç recommendation üretmediyse, generic ekle
        if not recommendations:
            if risk_score >= 75:
                recommendations = [
                    "Acil güvenlik önlemi alın ve bu IOC'yi bloke edin",
                    "Sistemleri izole edin ve detaylı forensic analiz yapın",
                    "SOC ekibini derhal bilgilendirin"
                ]
            elif risk_score >= 50:
                recommendations = [
                    "Güvenlik ekibini bilgilendirin ve izleme yapın",
                    "Log kayıtlarını detaylı inceleyin",
                    "Firewall ve IDS/IPS kurallarını gözden geçirin"
                ]
            elif risk_score >= 25:
                recommendations = [
                    "İzlemeye devam edin ve periyodik kontrol yapın",
                    "Ek doğrulama için başka kaynaklardan kontrol edin",
                    "Düşük öncelikli olay olarak kaydedin"
                ]
            else:
                recommendations = [
                    "Normal aktivite, acil aksiyon gerekmez",
                    "Rutin izleme yeterli",
                    "Allowlist'e eklemeyi değerlendirin"
                ]
        
        # Fallback for empty summaries
        if not summary_tr:
            summary_tr = f"Bu {ioc_type.value} için risk skoru {risk_score}/100 olarak hesaplandı."
        
        if not summary_en:
            summary_en = f"Risk score for this {ioc_type.value} is {risk_score}/100."
        
        # Fallback for empty findings
        if not key_findings:
            key_findings = ["AI tarafından spesifik bulgu üretilmedi, ham verilere bakınız"]
        
        # Fallback for empty tags
        if not tags:
            if risk_score >= 75:
                tags = ["high-risk", "malicious"]
            elif risk_score >= 50:
                tags = ["medium-risk", "suspicious"]
            elif risk_score >= 25:
                tags = ["low-risk"]
            else:
                tags = ["safe", "clean"]

        # Determine severity based on risk score
        severity = "LOW"
        for sev, (min_score, max_score) in self.SEVERITY_THRESHOLDS.items():
            if min_score <= risk_score <= max_score:
                severity = sev
                break

        # Calculate confidence based on available data
        confidence = self._calculate_confidence(provider_results)

        return ThreatAnalysis(
            risk_score=risk_score,
            severity=severity,
            summary_tr=summary_tr.strip(),
            summary_en=summary_en.strip(),
            key_findings=key_findings,
            recommendations=recommendations,
            tags=tags,
            confidence=confidence,
        )
    
    def _calculate_confidence(self, provider_results: Dict) -> float:
        """Calculate confidence score based on available data"""
        total_providers = len(provider_results)
        successful_providers = sum(
            1 for r in provider_results.values()
            if r.get("status") == "success"
        )
        
        if total_providers == 0:
            return 0.0
        
        return round(successful_providers / total_providers, 2)
    
    def _fallback_analysis(
        self,
        ioc: str,
        ioc_type: IOCType,
        provider_results: Dict,
        error: str,
    ) -> ThreatAnalysis:
        """Fallback rule-based analysis if AI fails"""
        # Simple rule-based scoring
        risk_score = 0
        findings = []
        
        # VirusTotal scoring
        if "VirusTotal" in provider_results:
            vt = provider_results["VirusTotal"]
            if vt.get("status") == "success" and vt.get("data"):
                malicious = vt["data"].get("malicious_count", 0)
                total = vt["data"].get("total_engines", 1)
                ratio = (malicious / total) * 100 if total > 0 else 0
                risk_score += min(40, ratio)
                if malicious > 0:
                    findings.append(f"{malicious} antivirüs motoru kötü amaçlı olarak tespit etti")
        
        # AbuseIPDB scoring
        if "AbuseIPDB" in provider_results:
            abuse = provider_results["AbuseIPDB"]
            if abuse.get("status") == "success" and abuse.get("data"):
                score = abuse["data"].get("abuse_confidence_score", 0)
                risk_score += min(40, score * 0.4)
                if score > 50:
                    findings.append(f"AbuseIPDB güven skoru: %{score}")
        
        # Shodan scoring
        if "Shodan" in provider_results:
            shodan = provider_results["Shodan"]
            if shodan.get("status") == "success" and shodan.get("data"):
                vulns = shodan["data"].get("vulns", [])
                if vulns:
                    risk_score += min(20, len(vulns) * 5)
                    findings.append(f"{len(vulns)} güvenlik açığı tespit edildi")
        
        risk_score = int(min(100, max(0, risk_score)))
        
        severity = "LOW"
        for sev, (min_score, max_score) in self.SEVERITY_THRESHOLDS.items():
            if min_score <= risk_score <= max_score:
                severity = sev
                break
        
        # Generate fallback recommendations based on risk score
        if risk_score >= 75:
            recommendations = [
                "Acil güvenlik önlemi alın",
                "Sistemleri izole edin",
                "Detaylı forensic analiz yapın"
            ]
        elif risk_score >= 50:
            recommendations = [
                "Güvenlik ekibini bilgilendirin",
                "Log kayıtlarını inceleyin",
                "Firewall kurallarını gözden geçirin"
            ]
        elif risk_score >= 25:
            recommendations = [
                "İzlemeye devam edin",
                "Ek doğrulama yapın"
            ]
        else:
            recommendations = [
                "Manuel inceleme önerilir",
                "Ek kaynaklardan doğrulama yapın"
            ]
        
        return ThreatAnalysis(
            risk_score=risk_score,
            severity=severity,
            summary_tr=f"AI analizi kullanılamadı, kural tabanlı analiz sonucu: Risk skoru {risk_score}/100",
            summary_en=f"AI analysis unavailable, rule-based analysis result: Risk score {risk_score}/100",
            key_findings=findings if findings else ["Yeterli veri yok"],
            recommendations=recommendations,
            tags=["fallback-analysis", "rule-based"],
            confidence=0.5,
        )
