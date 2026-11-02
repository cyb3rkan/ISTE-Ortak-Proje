"""
Report generation module
Supports JSON, Markdown, and terminal output formats
"""
import json
from typing import Dict, Any
from datetime import datetime
from pathlib import Path

from .config import Config
from .validators import IOCType
from .analyzer import ThreatAnalysis


class Reporter:
    """Generate reports in various formats"""
    
    # Color codes for terminal output
    COLORS = {
        "RED": "\033[91m",
        "GREEN": "\033[92m",
        "YELLOW": "\033[93m",
        "BLUE": "\033[94m",
        "MAGENTA": "\033[95m",
        "CYAN": "\033[96m",
        "WHITE": "\033[97m",
        "RESET": "\033[0m",
        "BOLD": "\033[1m",
    }
    
    SEVERITY_COLORS = {
        "LOW": "GREEN",
        "MEDIUM": "YELLOW",
        "HIGH": "YELLOW",
        "CRITICAL": "RED",
    }
    
    SEVERITY_EMOJI = {
        "LOW": "✅",
        "MEDIUM": "⚠️",
        "HIGH": "🔴",
        "CRITICAL": "🚨",
    }
    
    @staticmethod
    def generate_terminal_report(
        ioc: str,
        ioc_type: IOCType,
        provider_results: Dict[str, Any],
        ai_analysis: ThreatAnalysis,
    ) -> str:
        """Generate colorful terminal report"""
        c = Reporter.COLORS
        severity_color = c[Reporter.SEVERITY_COLORS.get(ai_analysis.severity, "WHITE")]
        severity_emoji = Reporter.SEVERITY_EMOJI.get(ai_analysis.severity, "ℹ️")
        
        report_lines = []
        
        # Header
        report_lines.append(f"\n{c['BOLD']}{'=' * 70}{c['RESET']}")
        report_lines.append(f"{c['BOLD']}{c['CYAN']}🔍 IOC ENRİCHMENT RAPORU{c['RESET']}")
        report_lines.append(f"{c['BOLD']}{'=' * 70}{c['RESET']}\n")
        
        # IOC Info
        report_lines.append(f"{c['BOLD']}Target:{c['RESET']} {c['WHITE']}{ioc}{c['RESET']}")
        report_lines.append(f"{c['BOLD']}Type:{c['RESET']} {c['BLUE']}{ioc_type.value.upper()}{c['RESET']}")
        report_lines.append(f"{c['BOLD']}Date:{c['RESET']} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"{c['BOLD']}Confidence:{c['RESET']} {ai_analysis.confidence * 100:.0f}%\n")
        
        # Risk Score
        report_lines.append(f"{c['BOLD']}{'─' * 70}{c['RESET']}")
        report_lines.append(
            f"{c['BOLD']}🎯 RISK SCORE:{c['RESET']} "
            f"{severity_color}{c['BOLD']}{ai_analysis.risk_score}/100{c['RESET']} "
            f"{severity_emoji} {severity_color}{c['BOLD']}{ai_analysis.severity}{c['RESET']}"
        )
        report_lines.append(f"{c['BOLD']}{'─' * 70}{c['RESET']}\n")
        
        # Provider Results
        report_lines.append(f"{c['BOLD']}{c['CYAN']}📊 THREAT INTELLIGENCE SOURCES{c['RESET']}")
        report_lines.append(f"{c['BOLD']}{'─' * 70}{c['RESET']}")
        
        for provider_name, result in provider_results.items():
            status = result.get("status", "unknown")
            
            if status == "success":
                status_icon = f"{c['GREEN']}✓{c['RESET']}"
                data = result.get("data", {})
                
                report_lines.append(f"\n{status_icon} {c['BOLD']}{provider_name}{c['RESET']}")
                
                # Provider-specific details
                if provider_name == "VirusTotal":
                    mal = data.get("malicious_count", 0)
                    sus = data.get("suspicious_count", 0)
                    total = data.get("total_engines", 0)
                    report_lines.append(f"  └─ Detection: {mal} malicious, {sus} suspicious / {total} engines")
                    
                elif provider_name == "AbuseIPDB":
                    score = data.get("abuse_confidence_score", 0)
                    reports = data.get("total_reports", 0)
                    report_lines.append(f"  └─ Confidence Score: {score}%, Total Reports: {reports}")
                    
                elif provider_name == "Shodan":
                    ports = data.get("ports", [])
                    vulns = data.get("vulns", [])
                    if ports:
                        report_lines.append(f"  └─ Open Ports: {', '.join(map(str, ports[:10]))}")
                    if vulns:
                        report_lines.append(f"  └─ Vulnerabilities: {', '.join(vulns[:5])}")
                    
                elif provider_name == "AlienVault OTX":
                    pulses = data.get("pulse_count", 0)
                    report_lines.append(f"  └─ Threat Pulses: {pulses}")
                    
            elif status == "not_found":
                report_lines.append(f"\n{c['YELLOW']}ℹ{c['RESET']} {c['BOLD']}{provider_name}{c['RESET']}")
                report_lines.append(f"  └─ Not found in database")
                
            else:
                report_lines.append(f"\n{c['RED']}✗{c['RESET']} {c['BOLD']}{provider_name}{c['RESET']}")
                error = result.get("error", "Unknown error")
                
                # Shorten long error messages
                if len(error) > 80:
                    if "HTTPSConnectionPool" in error or "Max retries" in error or "Connection aborted" in error:
                        error = "Connection timeout (network/firewall issue)"
                    elif "ProtocolError" in error:
                        error = "Network protocol error (Windows compatibility issue)"
                    else:
                        error = error[:77] + "..."
                
                report_lines.append(f"  └─ {error}")
        
        report_lines.append(f"\n{c['BOLD']}{'─' * 70}{c['RESET']}\n")
        
        # AI Analysis
        report_lines.append(f"{c['BOLD']}{c['MAGENTA']}🤖 AI ANALİZİ{c['RESET']}")
        report_lines.append(f"{c['BOLD']}{'─' * 70}{c['RESET']}")
        report_lines.append(f"\n{c['BOLD']}Türkçe Özet:{c['RESET']}")
        report_lines.append(f"{ai_analysis.summary_tr}\n")
        
        if ai_analysis.key_findings:
            report_lines.append(f"{c['BOLD']}Önemli Bulgular:{c['RESET']}")
            for finding in ai_analysis.key_findings:
                report_lines.append(f"  • {finding}")
            report_lines.append("")
        
        if ai_analysis.recommendations:
            report_lines.append(f"{c['BOLD']}{c['YELLOW']}⚡ ÖNERİLER{c['RESET']}")
            for rec in ai_analysis.recommendations:
                report_lines.append(f"  • {rec}")
            report_lines.append("")
        
        if ai_analysis.tags:
            tags_str = ", ".join(f"{c['CYAN']}{tag}{c['RESET']}" for tag in ai_analysis.tags)
            report_lines.append(f"{c['BOLD']}Tags:{c['RESET']} {tags_str}\n")
        
        # Footer
        report_lines.append(f"{c['BOLD']}{'=' * 70}{c['RESET']}\n")
        
        return "\n".join(report_lines)
    
    @staticmethod
    def generate_json_report(
        ioc: str,
        ioc_type: IOCType,
        provider_results: Dict[str, Any],
        ai_analysis: ThreatAnalysis,
    ) -> str:
        """Generate JSON report"""
        report = {
            "metadata": {
                "ioc": ioc,
                "ioc_type": ioc_type.value,
                "timestamp": datetime.now().isoformat(),
                "version": "1.0",
            },
            "analysis": {
                "risk_score": ai_analysis.risk_score,
                "severity": ai_analysis.severity,
                "confidence": ai_analysis.confidence,
                "summary": {
                    "turkish": ai_analysis.summary_tr,
                    "english": ai_analysis.summary_en,
                },
                "key_findings": ai_analysis.key_findings,
                "recommendations": ai_analysis.recommendations,
                "tags": ai_analysis.tags,
            },
            "threat_intelligence": provider_results,
        }
        
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    @staticmethod
    def generate_markdown_report(
        ioc: str,
        ioc_type: IOCType,
        provider_results: Dict[str, Any],
        ai_analysis: ThreatAnalysis,
    ) -> str:
        """Generate Markdown report"""
        severity_emoji = Reporter.SEVERITY_EMOJI.get(ai_analysis.severity, "ℹ️")
        
        md_lines = []
        
        # Header
        md_lines.append("# 🔍 IOC Enrichment Report\n")
        md_lines.append("---\n")
        
        # Metadata
        md_lines.append("## 📋 Metadata\n")
        md_lines.append(f"- **IOC:** `{ioc}`")
        md_lines.append(f"- **Type:** {ioc_type.value.upper()}")
        md_lines.append(f"- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md_lines.append(f"- **Confidence:** {ai_analysis.confidence * 100:.0f}%\n")
        
        # Risk Assessment
        md_lines.append("---\n")
        md_lines.append("## 🎯 Risk Assessment\n")
        md_lines.append(f"### {severity_emoji} Risk Score: {ai_analysis.risk_score}/100 ({ai_analysis.severity})\n")
        
        # AI Summary
        md_lines.append("### 🤖 AI Analysis\n")
        md_lines.append(f"> {ai_analysis.summary_tr}\n")
        
        if ai_analysis.key_findings:
            md_lines.append("#### Key Findings\n")
            for finding in ai_analysis.key_findings:
                md_lines.append(f"- {finding}")
            md_lines.append("")
        
        if ai_analysis.recommendations:
            md_lines.append("#### ⚡ Recommendations\n")
            for rec in ai_analysis.recommendations:
                md_lines.append(f"- {rec}")
            md_lines.append("")
        
        # Provider Results
        md_lines.append("---\n")
        md_lines.append("## 📊 Threat Intelligence Sources\n")
        
        for provider_name, result in provider_results.items():
            status = result.get("status", "unknown")
            
            md_lines.append(f"### {provider_name}\n")
            
            if status == "success":
                md_lines.append("**Status:** ✅ Success\n")
                data = result.get("data", {})
                
                md_lines.append("**Data:**")
                md_lines.append("```json")
                md_lines.append(json.dumps(data, indent=2, ensure_ascii=False))
                md_lines.append("```\n")
                
            else:
                icon = "❌" if status == "error" else "ℹ️"
                md_lines.append(f"**Status:** {icon} {status.upper()}")
                error = result.get("error", "")
                if error:
                    md_lines.append(f"**Error:** {error}\n")
        
        # Tags
        if ai_analysis.tags:
            md_lines.append("---\n")
            md_lines.append("## 🏷️ Tags\n")
            md_lines.append(", ".join(f"`{tag}`" for tag in ai_analysis.tags))
            md_lines.append("\n")
        
        # Footer
        md_lines.append("---\n")
        md_lines.append("*Generated by IOC Enricher Agent*")
        
        return "\n".join(md_lines)
    
    @staticmethod
    def save_report(content: str, filename: str, format_type: str) -> Path:
        """
        Save report to file
        
        Args:
            content: Report content
            filename: Base filename (without extension)
            format_type: Format type (json, md, txt)
            
        Returns:
            Path to saved file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = Config.REPORTS_DIR / f"{filename}_{timestamp}.{format_type}"
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        return file_path
