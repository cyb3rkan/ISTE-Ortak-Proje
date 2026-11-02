#!/usr/bin/env python3
"""
IOC Enricher Agent - Command Line Interface
AI-Powered Indicator of Compromise Enrichment Tool
"""
import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.enricher import IOCEnricher
from src.config import Config


def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║            IOC ENRICHER AGENT - AI-Powered Analysis              ║
║                                                                  ║
║     Siber Güvenlik Tehdit İstihbaratı Zenginleştirme Aracı       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_provider_status(enricher: IOCEnricher):
    """Print status of all providers"""
    status = enricher.get_provider_status()
    
    print("\n📡 Provider Status:")
    print("─" * 40)
    
    for provider, enabled in status.items():
        icon = "✅" if enabled else "❌"
        status_text = "Enabled" if enabled else "Disabled"
        print(f"  {icon} {provider:20} {status_text}")
    
    print()


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="IOC Enricher Agent - AI-Powered Threat Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze single IP
  python main.py --ip 8.8.8.8
  
  # Analyze domain
  python main.py --domain malicious-site.com
  
  # Analyze file hash
  python main.py --hash 44d88612fea8a8f36de82e1278abb02f
  
  # Analyze URL
  python main.py --url http://malicious-site.com/malware.exe
  
  # Batch analysis from file
  python main.py --file iocs.txt
  
  # Generate JSON report
  python main.py --ip 8.8.8.8 --format json --save
  
  # Generate Markdown report
  python main.py --domain example.com --format markdown --save
        """
    )
    
    # IOC input arguments (mutually exclusive)
    ioc_group = parser.add_mutually_exclusive_group(required=False)
    ioc_group.add_argument(
        "--ip",
        type=str,
        help="IP address to analyze"
    )
    ioc_group.add_argument(
        "--domain",
        type=str,
        help="Domain name to analyze"
    )
    ioc_group.add_argument(
        "--hash",
        type=str,
        help="File hash (MD5, SHA1, SHA256) to analyze"
    )
    ioc_group.add_argument(
        "--url",
        type=str,
        help="URL to analyze"
    )
    ioc_group.add_argument(
        "--email",
        type=str,
        help="Email address to analyze"
    )
    ioc_group.add_argument(
        "--ioc",
        type=str,
        help="Any IOC (auto-detect type)"
    )
    ioc_group.add_argument(
        "--file",
        type=str,
        help="File containing IOCs (one per line)"
    )
    
    # Output arguments
    parser.add_argument(
        "--format",
        choices=["terminal", "json", "markdown"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save report to file"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output file path (optional)"
    )
    
    # Utility arguments
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show provider status and exit"
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Don't show banner"
    )
    
    args = parser.parse_args()
    
    # Show banner unless disabled
    if not args.no_banner:
        print_banner()
    
    # Show version
    if args.version:
        from src import __version__
        print(f"Version: {__version__}")
        return 0
    
    try:
        # Initialize enricher
        enricher = IOCEnricher()
        
        # Show provider status
        if args.status:
            print_provider_status(enricher)
            return 0
        
        # Check if any IOC was provided
        if not any([args.ip, args.domain, args.hash, args.url, args.email, args.ioc, args.file]):
            parser.print_help()
            print("\n❌ Error: Please provide an IOC to analyze")
            return 1
        
        # Process batch file
        if args.file:
            file_path = Path(args.file)
            if not file_path.exists():
                print(f"❌ Error: File not found: {args.file}")
                return 1
            
            with open(file_path, "r") as f:
                iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            
            if not iocs:
                print(f"❌ Error: No IOCs found in file: {args.file}")
                return 1
            
            results = enricher.enrich_batch(
                iocs,
                output_format=args.format,
                save_reports=args.save,
            )
            
            # Print summary
            success_count = sum(1 for r in results if r.get("success"))
            print(f"📊 Summary: {success_count}/{len(results)} IOCs analyzed successfully")
            
            return 0
        
        # Process single IOC
        ioc = args.ip or args.domain or args.hash or args.url or args.email or args.ioc
        
        result = enricher.enrich(
            ioc,
            output_format=args.format,
            save_report=args.save,
        )
        
        if not result.get("success"):
            print(f"\n❌ Error: {result.get('error')}")
            return 1
        
        # Print report if not terminal format
        if args.format != "terminal":
            print(result["report"])
        
        # Show execution time
        print(f"⏱️  Execution time: {result['execution_time']}s")
        
        # Show saved report path
        if result.get("report_path"):
            print(f"💾 Report saved: {result['report_path']}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        return 130
        
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
