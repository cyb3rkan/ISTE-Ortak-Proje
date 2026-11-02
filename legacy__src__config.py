"""
Configuration management for IOC Enricher
"""
import os
from pathlib import Path
from dotenv import load_dotenv
from typing import Optional

# Load environment variables
load_dotenv()

class Config:
    """Application configuration"""
    
    # Base paths
    BASE_DIR = Path(__file__).resolve().parent.parent
    DATA_DIR = BASE_DIR / "data"
    CACHE_DIR = DATA_DIR / "cache"
    REPORTS_DIR = BASE_DIR / "reports"
    LOGS_DIR = BASE_DIR / "logs"
    
    # API Keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    
    # AI Provider Selection
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "gemini")  # "openai" or "gemini"
    
    # OpenAI Settings
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    OPENAI_MAX_TOKENS: int = int(os.getenv("OPENAI_MAX_TOKENS", "2000"))
    OPENAI_TEMPERATURE: float = float(os.getenv("OPENAI_TEMPERATURE", "0.3"))
    
    # Gemini Settings - Using stable Flash model
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    GEMINI_MAX_TOKENS: int = int(os.getenv("GEMINI_MAX_TOKENS", "2000"))
    GEMINI_TEMPERATURE: float = float(os.getenv("GEMINI_TEMPERATURE", "0.3"))
    
    # Cache Settings
    ENABLE_CACHE: bool = os.getenv("ENABLE_CACHE", "true").lower() == "true"
    CACHE_TTL_HOURS: int = int(os.getenv("CACHE_TTL_HOURS", "24"))
    
    # Rate Limiting - Optimized for Windows
    MAX_CONCURRENT_REQUESTS: int = int(os.getenv("MAX_CONCURRENT_REQUESTS", "3"))
    REQUEST_TIMEOUT_SECONDS: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "90"))
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: str = os.getenv("LOG_FILE", "logs/ioc_enricher.log")
    
    @classmethod
    def validate(cls) -> list[str]:
        """
        Validate required configuration
        Returns list of missing/invalid configs
        """
        errors = []
        
        # Check critical API keys
        if not cls.VIRUSTOTAL_API_KEY:
            errors.append("VIRUSTOTAL_API_KEY is missing")
        if not cls.ABUSEIPDB_API_KEY:
            errors.append("ABUSEIPDB_API_KEY is missing")
        
        # Check AI provider based on selection
        if cls.AI_PROVIDER == "openai":
            if not cls.OPENAI_API_KEY:
                errors.append("OPENAI_API_KEY is missing (AI_PROVIDER=openai)")
        elif cls.AI_PROVIDER == "gemini":
            if not cls.GEMINI_API_KEY:
                errors.append("GEMINI_API_KEY is missing (AI_PROVIDER=gemini)")
        else:
            errors.append(f"Invalid AI_PROVIDER: {cls.AI_PROVIDER} (must be 'openai' or 'gemini')")
            
        return errors
    
    @classmethod
    def create_directories(cls) -> None:
        """Create necessary directories if they don't exist"""
        for directory in [cls.DATA_DIR, cls.CACHE_DIR, cls.REPORTS_DIR, cls.LOGS_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def get_provider_status(cls) -> dict[str, bool]:
        """Get status of all providers"""
        return {
            "VirusTotal": bool(cls.VIRUSTOTAL_API_KEY),
            "AbuseIPDB": bool(cls.ABUSEIPDB_API_KEY),
            "Shodan": bool(cls.SHODAN_API_KEY),
            "AlienVault OTX": bool(cls.OTX_API_KEY),
            f"AI ({cls.AI_PROVIDER.upper()})": (
                bool(cls.OPENAI_API_KEY) if cls.AI_PROVIDER == "openai" 
                else bool(cls.GEMINI_API_KEY)
            ),
        }


# Create directories on import
Config.create_directories()
