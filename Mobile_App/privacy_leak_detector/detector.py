#!/usr/bin/env python3
"""
Mobile App Privacy Leakage Detector
Main CLI entry point for static and dynamic analysis.

Usage:
    python detector.py --apk sample.apk --traffic traffic.json --out report
    python detector.py --apk sample.apk --out report
    python detector.py --traffic traffic.json --out report
"""

import os
import sys
import argparse
from typing import Optional, Dict, Any

# Import analyzer modules
from static_analyzer import analyze_apk
from dynamic_analyzer import analyze_traffic
from report_generator import generate_report

# Try to import colorama for colored output
try:
    from colorama import init, Fore, Style
    init()
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""


def print_banner():
    """Print the tool banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║         MOBILE APP PRIVACY LEAKAGE DETECTOR v1.0                     ║
║         Static + Dynamic Analysis Tool                               ║
║                                                                      ║
║         Analyzes Android APKs and network traffic for                ║
║         privacy data leakage and security issues.                    ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    if COLORAMA_AVAILABLE:
        print(Fore.CYAN + banner + Style.RESET_ALL)
    else:
        print(banner)


def print_status(message: str, status: str = "info"):
    """Print a status message with appropriate formatting."""
    if COLORAMA_AVAILABLE:
        colors = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED
        }
        color = colors.get(status, Fore.WHITE)
        print(f"{color}[*] {message}{Style.RESET_ALL}")
    else:
        prefixes = {
            "info": "[*]",
            "success": "[+]",
            "warning": "[!]",
            "error": "[-]"
        }
        prefix = prefixes.get(status, "[*]")
        print(f"{prefix} {message}")


def validate_inputs(apk_path: Optional[str], traffic_path: Optional[str]) -> bool:
    """Validate input file paths."""
    valid = True

    if apk_path:
        if not os.path.exists(apk_path):
            print_status(f"APK file not found: {apk_path}", "error")
            valid = False
        elif not apk_path.lower().endswith('.apk'):
            print_status(f"File is not an APK: {apk_path}", "error")
            valid = False

    if traffic_path:
        if not os.path.exists(traffic_path):
            print_status(f"Traffic log file not found: {traffic_path}", "error")
            valid = False

    if not apk_path and not traffic_path:
        print_status("At least one input file (--apk or --traffic) is required", "error")
        valid = False

    return valid


def run_analysis(
    apk_path: Optional[str] = None,
    traffic_path: Optional[str] = None,
    output_prefix: str = "report"
) -> Dict[str, Any]:
    """
    Run the complete privacy analysis pipeline.

    Args:
        apk_path: Path to Android APK file (optional)
        traffic_path: Path to mitmproxy traffic log (optional)
        output_prefix: Prefix for output report files

    Returns:
        Dictionary containing analysis results and report paths
    """
    results = {
        "static_analysis": None,
        "dynamic_analysis": None,
        "reports": None,
        "success": False
    }

    # Validate inputs
    if not validate_inputs(apk_path, traffic_path):
        return results

    # Run static analysis
    if apk_path:
        print_status("Starting static analysis...", "info")
        try:
            results["static_analysis"] = analyze_apk(apk_path)
            print_status("Static analysis completed", "success")
        except Exception as e:
            print_status(f"Static analysis failed: {e}", "error")
            # Continue with dynamic analysis even if static fails

    # Run dynamic analysis
    if traffic_path:
        print_status("Starting dynamic analysis...", "info")
        try:
            results["dynamic_analysis"] = analyze_traffic(traffic_path)
            print_status("Dynamic analysis completed", "success")
        except Exception as e:
            print_status(f"Dynamic analysis failed: {e}", "error")
            # Continue with report generation even if dynamic fails

    # Generate reports if we have any results
    if results["static_analysis"] or results["dynamic_analysis"]:
        print_status("Generating reports...", "info")
        try:
            results["reports"] = generate_report(
                results["static_analysis"],
                results["dynamic_analysis"],
                output_prefix
            )
            results["success"] = True
            print_status("Analysis complete!", "success")
        except Exception as e:
            print_status(f"Report generation failed: {e}", "error")
    else:
        print_status("No analysis results to report", "warning")

    return results


def create_sample_traffic_file(path: str):
    """Create a sample traffic log file for testing."""
    import json

    sample_traffic = [
        {
            "request": {
                "method": "POST",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/analytics/track",
                "headers": [
                    ["Content-Type", "application/json"],
                    ["User-Agent", "ExampleApp/1.0"]
                ],
                "content": '{"event":"app_open","device_id":"a1b2c3d4e5f6g7h8","lat":37.7749,"lng":-122.4194,"email":"user@example.com"}'
            },
            "response": {
                "status_code": 200,
                "headers": [["Content-Type", "application/json"]],
                "content": '{"status":"ok"}'
            }
        },
        {
            "request": {
                "method": "GET",
                "scheme": "https",
                "host": "google-analytics.com",
                "path": "/collect?v=1&tid=UA-123456&cid=device123",
                "headers": [],
                "content": ""
            },
            "response": {
                "status_code": 200,
                "headers": [],
                "content": ""
            }
        }
    ]

    with open(path, 'w') as f:
        json.dump(sample_traffic, f, indent=2)

    print_status(f"Created sample traffic file: {path}", "success")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Mobile App Privacy Leakage Detector - Analyze APKs and network traffic for privacy issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Analyze APK only:
    python detector.py --apk app.apk --out report

  Analyze traffic only:
    python detector.py --traffic traffic.json --out report

  Full analysis:
    python detector.py --apk app.apk --traffic traffic.json --out report

  Create sample traffic file:
    python detector.py --create-sample sample_traffic.json

Output:
  The tool generates two report files:
    - <output_prefix>.json  - Machine-readable JSON report
    - <output_prefix>.txt   - Human-readable text report
        """
    )

    parser.add_argument(
        "--apk", "-a",
        metavar="FILE",
        help="Path to Android APK file for static analysis"
    )

    parser.add_argument(
        "--traffic", "-t",
        metavar="FILE",
        help="Path to mitmproxy traffic log file (.json) for dynamic analysis"
    )

    parser.add_argument(
        "--out", "-o",
        metavar="PREFIX",
        default="privacy_report",
        help="Output file prefix (default: privacy_report)"
    )

    parser.add_argument(
        "--create-sample",
        metavar="FILE",
        help="Create a sample traffic log file for testing"
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress banner and status messages"
    )

    parser.add_argument(
        "--version", "-v",
        action="version",
        version="Mobile App Privacy Leakage Detector v1.0"
    )

    args = parser.parse_args()

    # Print banner unless quiet mode
    if not args.quiet:
        print_banner()

    # Handle sample file creation
    if args.create_sample:
        create_sample_traffic_file(args.create_sample)
        return 0

    # Check if at least one input is provided
    if not args.apk and not args.traffic:
        parser.print_help()
        print("\nError: At least one input file (--apk or --traffic) is required")
        return 1

    # Run analysis
    results = run_analysis(
        apk_path=args.apk,
        traffic_path=args.traffic,
        output_prefix=args.out
    )

    if results["success"]:
        print("\n" + "=" * 60)
        print("Report files generated:")
        if results["reports"]:
            print(f"  - JSON: {results['reports'].get('json_report', 'N/A')}")
            print(f"  - Text: {results['reports'].get('text_report', 'N/A')}")
            print(f"  - Risk Level: {results['reports'].get('risk_level', 'N/A')}")
        print("=" * 60)
        return 0
    else:
        print_status("Analysis failed or incomplete", "error")
        return 1


if __name__ == "__main__":
    sys.exit(main())
