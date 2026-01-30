#!/usr/bin/env python3
"""
Report Generator Module for Mobile App Privacy Leakage Detection
Combines static and dynamic analysis results into comprehensive reports.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

# Try to import colorama for colored output
try:
    from colorama import init, Fore, Style
    init()
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback: define empty color codes
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""


def calculate_risk_level(static_results: Dict, dynamic_results: Dict) -> str:
    """
    Calculate overall risk level based on analysis results.

    Risk scoring:
    - HIGH: Critical privacy issues detected (device IDs, location being leaked)
    - MEDIUM: Moderate privacy concerns (tracking, email leakage)
    - LOW: Minimal privacy concerns
    """
    score = 0

    # Static analysis scoring
    if static_results:
        # High-risk permissions
        for perm in static_results.get("permissions", []):
            if perm.get("risk_level") == "HIGH":
                score += 15
            elif perm.get("risk_level") == "MEDIUM":
                score += 5

        # Sensitive APIs
        for api in static_results.get("sensitive_apis", []):
            if api.get("risk_level") == "HIGH":
                score += 20
            elif api.get("risk_level") == "MEDIUM":
                score += 10

        # Network APIs with sensitive API combination
        if static_results.get("network_apis") and static_results.get("sensitive_apis"):
            score += 15  # Bonus for having both network capability and sensitive data access

    # Dynamic analysis scoring
    if dynamic_results:
        # Leaked data
        for leak in dynamic_results.get("leaked_data_matches", []):
            if leak.get("risk_level") == "HIGH":
                score += 25
            elif leak.get("risk_level") == "MEDIUM":
                score += 10

        # Tracking domains
        tracking_count = len(dynamic_results.get("tracking_domains", []))
        score += min(tracking_count * 5, 20)  # Cap at 20 points

    # Determine risk level
    if score >= 100:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def get_risk_color(risk_level: str) -> str:
    """Get color code for risk level."""
    if not COLORAMA_AVAILABLE:
        return ""

    colors = {
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.GREEN
    }
    return colors.get(risk_level, Fore.WHITE)


def format_section_header(title: str, width: int = 70) -> str:
    """Format a section header."""
    return f"\n{'='*width}\n{title.center(width)}\n{'='*width}\n"


def generate_text_report(
    static_results: Dict,
    dynamic_results: Dict,
    risk_level: str,
    output_path: str
) -> str:
    """
    Generate a human-readable text report.
    """
    lines = []

    # Header
    lines.append("=" * 70)
    lines.append("MOBILE APP PRIVACY LEAKAGE DETECTION REPORT".center(70))
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Overall Risk Assessment
    lines.append("-" * 70)
    lines.append("OVERALL RISK ASSESSMENT".center(70))
    lines.append("-" * 70)
    lines.append(f"Risk Level: {risk_level}")
    lines.append("")

    # Risk explanation
    if risk_level == "HIGH":
        lines.append("WARNING: Critical privacy concerns detected!")
        lines.append("The application shows evidence of collecting and potentially")
        lines.append("transmitting sensitive personal data without clear justification.")
    elif risk_level == "MEDIUM":
        lines.append("CAUTION: Moderate privacy concerns detected.")
        lines.append("The application accesses some sensitive data and communicates")
        lines.append("with tracking services.")
    else:
        lines.append("LOW RISK: Minimal privacy concerns detected.")
        lines.append("The application appears to have limited access to sensitive data.")
    lines.append("")

    # App Information (if available)
    if static_results and static_results.get("app_info"):
        app_info = static_results["app_info"]
        lines.append("-" * 70)
        lines.append("APPLICATION INFORMATION".center(70))
        lines.append("-" * 70)
        if app_info.get("app_name"):
            lines.append(f"App Name: {app_info.get('app_name', 'N/A')}")
        if app_info.get("package_name"):
            lines.append(f"Package: {app_info.get('package_name', 'N/A')}")
        if app_info.get("version_name"):
            lines.append(f"Version: {app_info.get('version_name', 'N/A')} (Code: {app_info.get('version_code', 'N/A')})")
        if app_info.get("min_sdk"):
            lines.append(f"Min SDK: {app_info.get('min_sdk', 'N/A')} | Target SDK: {app_info.get('target_sdk', 'N/A')}")
        lines.append("")

    # Static Analysis Results
    if static_results:
        lines.append("-" * 70)
        lines.append("STATIC ANALYSIS RESULTS".center(70))
        lines.append("-" * 70)
        lines.append("")

        # Permissions
        permissions = static_results.get("permissions", [])
        lines.append(f"PERMISSIONS ({len(permissions)} found):")
        lines.append("-" * 40)

        if permissions:
            # Sort by risk level
            high_perms = [p for p in permissions if p.get("risk_level") == "HIGH"]
            medium_perms = [p for p in permissions if p.get("risk_level") == "MEDIUM"]
            low_perms = [p for p in permissions if p.get("risk_level") == "LOW"]

            if high_perms:
                lines.append("\n  [HIGH RISK]")
                for perm in high_perms:
                    perm_name = perm.get("permission", "").replace("android.permission.", "")
                    lines.append(f"    - {perm_name}")
                    if perm.get("description"):
                        lines.append(f"      ({perm.get('description')})")

            if medium_perms:
                lines.append("\n  [MEDIUM RISK]")
                for perm in medium_perms:
                    perm_name = perm.get("permission", "").replace("android.permission.", "")
                    lines.append(f"    - {perm_name}")

            if low_perms:
                lines.append("\n  [LOW RISK]")
                for perm in low_perms[:10]:  # Limit low risk to 10
                    perm_name = perm.get("permission", "").replace("android.permission.", "")
                    lines.append(f"    - {perm_name}")
                if len(low_perms) > 10:
                    lines.append(f"    ... and {len(low_perms) - 10} more")
        else:
            lines.append("  No permissions found")

        lines.append("")

        # Sensitive APIs
        sensitive_apis = static_results.get("sensitive_apis", [])
        lines.append(f"SENSITIVE APIs ({len(sensitive_apis)} found):")
        lines.append("-" * 40)

        if sensitive_apis:
            for api in sensitive_apis:
                risk = api.get("risk_level", "UNKNOWN")
                lines.append(f"  [{risk}] {api.get('api', 'Unknown')}")
                if api.get("description"):
                    lines.append(f"         {api.get('description')}")
        else:
            lines.append("  No sensitive APIs detected")

        lines.append("")

        # Network APIs
        network_apis = static_results.get("network_apis", [])
        lines.append(f"NETWORK APIs ({len(network_apis)} found):")
        lines.append("-" * 40)

        if network_apis:
            for api in network_apis:
                lines.append(f"  - {api.get('api', 'Unknown')}: {api.get('description', '')}")
        else:
            lines.append("  No network APIs detected")

        lines.append("")

    # Dynamic Analysis Results
    if dynamic_results:
        lines.append("-" * 70)
        lines.append("DYNAMIC ANALYSIS RESULTS".center(70))
        lines.append("-" * 70)
        lines.append("")

        summary = dynamic_results.get("analysis_summary", {})
        lines.append(f"Total HTTP Flows Analyzed: {summary.get('total_flows', 0)}")
        lines.append(f"Unique Hosts Contacted: {summary.get('unique_hosts', 0)}")
        lines.append(f"Tracking Domains Found: {summary.get('tracking_domains_contacted', 0)}")
        lines.append("")

        # Tracking domains
        tracking = dynamic_results.get("tracking_domains", [])
        if tracking:
            lines.append("TRACKING/ANALYTICS DOMAINS:")
            lines.append("-" * 40)
            for domain in tracking:
                lines.append(f"  - {domain}")
            lines.append("")

        # Data leaks
        leaks = dynamic_results.get("leaked_data_matches", [])
        lines.append(f"DATA LEAKS DETECTED ({len(leaks)} found):")
        lines.append("-" * 40)

        if leaks:
            # Group by type
            leak_types = {}
            for leak in leaks:
                leak_type = leak.get("type", "unknown")
                if leak_type not in leak_types:
                    leak_types[leak_type] = []
                leak_types[leak_type].append(leak)

            for leak_type, type_leaks in leak_types.items():
                risk = type_leaks[0].get("risk_level", "UNKNOWN")
                lines.append(f"\n  [{risk}] {leak_type.upper().replace('_', ' ')}:")
                for leak in type_leaks[:5]:  # Limit to 5 per type
                    value = leak.get("value", "")[:50]  # Truncate
                    location = leak.get("location", "")
                    lines.append(f"       Value: {value}")
                    if location:
                        lines.append(f"       Found in: {location}")
                if len(type_leaks) > 5:
                    lines.append(f"       ... and {len(type_leaks) - 5} more")
        else:
            lines.append("  No data leaks detected in traffic")

        lines.append("")

        # URLs contacted (sample)
        urls = dynamic_results.get("urls", [])
        if urls:
            lines.append(f"SAMPLE URLs CONTACTED ({len(urls)} total):")
            lines.append("-" * 40)
            for url in urls[:10]:
                # Truncate long URLs
                display_url = url[:80] + "..." if len(url) > 80 else url
                lines.append(f"  - {display_url}")
            if len(urls) > 10:
                lines.append(f"  ... and {len(urls) - 10} more")
            lines.append("")

    # Recommendations
    lines.append("-" * 70)
    lines.append("RECOMMENDATIONS".center(70))
    lines.append("-" * 70)

    recommendations = generate_recommendations(static_results, dynamic_results, risk_level)
    for i, rec in enumerate(recommendations, 1):
        lines.append(f"{i}. {rec}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT".center(70))
    lines.append("=" * 70)

    # Write to file
    report_text = "\n".join(lines)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report_text)

    return report_text


def generate_json_report(
    static_results: Dict,
    dynamic_results: Dict,
    risk_level: str,
    output_path: str
) -> Dict:
    """
    Generate a JSON report for programmatic access.
    """
    report = {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool_name": "Mobile App Privacy Leakage Detector",
            "version": "1.0.0"
        },
        "risk_assessment": {
            "overall_risk_level": risk_level,
            "risk_factors": []
        },
        "static_analysis": static_results or {},
        "dynamic_analysis": dynamic_results or {},
        "recommendations": generate_recommendations(static_results, dynamic_results, risk_level)
    }

    # Add risk factors
    risk_factors = []

    if static_results:
        high_perms = sum(1 for p in static_results.get("permissions", []) if p.get("risk_level") == "HIGH")
        if high_perms > 0:
            risk_factors.append(f"{high_perms} high-risk permissions requested")

        sensitive_apis = len(static_results.get("sensitive_apis", []))
        if sensitive_apis > 0:
            risk_factors.append(f"{sensitive_apis} sensitive APIs detected in code")

    if dynamic_results:
        leaks = len(dynamic_results.get("leaked_data_matches", []))
        if leaks > 0:
            risk_factors.append(f"{leaks} potential data leaks detected in traffic")

        tracking = len(dynamic_results.get("tracking_domains", []))
        if tracking > 0:
            risk_factors.append(f"{tracking} tracking domains contacted")

    report["risk_assessment"]["risk_factors"] = risk_factors

    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)

    return report


def generate_recommendations(
    static_results: Optional[Dict],
    dynamic_results: Optional[Dict],
    risk_level: str
) -> List[str]:
    """
    Generate security recommendations based on analysis results.
    """
    recommendations = []

    if risk_level == "HIGH":
        recommendations.append(
            "CRITICAL: Review the application's data collection practices immediately."
        )

    if static_results:
        # Permission recommendations
        high_perms = [p for p in static_results.get("permissions", []) if p.get("risk_level") == "HIGH"]
        if high_perms:
            recommendations.append(
                f"Review the necessity of {len(high_perms)} high-risk permissions. "
                "Consider if all permissions are essential for app functionality."
            )

        # Location permissions
        location_perms = [p for p in static_results.get("permissions", [])
                        if "LOCATION" in p.get("permission", "")]
        if location_perms:
            recommendations.append(
                "Location access detected. Verify that location data is only collected "
                "when necessary and users are properly informed."
            )

        # Sensitive APIs with network capability
        if static_results.get("sensitive_apis") and static_results.get("network_apis"):
            recommendations.append(
                "The app has both sensitive data access and network capabilities. "
                "Audit data flows to ensure sensitive data is not transmitted unnecessarily."
            )

    if dynamic_results:
        # Data leak recommendations
        leaks = dynamic_results.get("leaked_data_matches", [])
        if leaks:
            leak_types = set(l.get("type", "") for l in leaks)
            recommendations.append(
                f"Data leaks detected ({', '.join(leak_types)}). "
                "Implement data minimization and ensure only necessary data is transmitted."
            )

        # Tracking recommendations
        tracking = dynamic_results.get("tracking_domains", [])
        if tracking:
            recommendations.append(
                f"{len(tracking)} tracking/analytics services detected. "
                "Review third-party SDKs and ensure compliance with privacy regulations."
            )

        # HTTPS recommendations
        urls = dynamic_results.get("urls", [])
        http_urls = [u for u in urls if u.startswith("http://")]
        if http_urls:
            recommendations.append(
                f"{len(http_urls)} unencrypted HTTP connections detected. "
                "Migrate all network traffic to HTTPS for secure transmission."
            )

    # General recommendations
    if not recommendations:
        recommendations.append(
            "No critical issues found. Continue monitoring app behavior "
            "and keep dependencies updated."
        )

    recommendations.append(
        "Consider implementing a privacy policy that clearly explains data collection practices."
    )
    recommendations.append(
        "Regularly audit third-party libraries and SDKs for privacy compliance."
    )

    return recommendations


def print_summary(
    static_results: Optional[Dict],
    dynamic_results: Optional[Dict],
    risk_level: str
):
    """
    Print a colored summary to console.
    """
    risk_color = get_risk_color(risk_level)
    reset = Style.RESET_ALL if COLORAMA_AVAILABLE else ""

    print("\n" + "=" * 60)
    print("PRIVACY ANALYSIS SUMMARY".center(60))
    print("=" * 60)

    print(f"\nOverall Risk Level: {risk_color}{risk_level}{reset}")

    if static_results:
        summary = static_results.get("analysis_summary", {})
        print(f"\nStatic Analysis:")
        print(f"  - Permissions: {summary.get('total_permissions', 0)} "
              f"({summary.get('high_risk_permissions', 0)} high-risk)")
        print(f"  - Sensitive APIs: {summary.get('sensitive_apis_found', 0)}")
        print(f"  - Network APIs: {summary.get('network_apis_found', 0)}")

    if dynamic_results:
        summary = dynamic_results.get("analysis_summary", {})
        print(f"\nDynamic Analysis:")
        print(f"  - HTTP Flows: {summary.get('total_flows', 0)}")
        print(f"  - Data Leaks: {summary.get('total_leaks_detected', 0)} "
              f"({summary.get('high_risk_leaks', 0)} high-risk)")
        print(f"  - Tracking Domains: {summary.get('tracking_domains_contacted', 0)}")

    print("\n" + "=" * 60)


def generate_report(
    static_results: Optional[Dict],
    dynamic_results: Optional[Dict],
    output_prefix: str
) -> Dict[str, str]:
    """
    Main function to generate comprehensive analysis reports.

    Args:
        static_results: Results from static APK analysis
        dynamic_results: Results from dynamic traffic analysis
        output_prefix: Prefix for output files (e.g., "report" -> "report.json", "report.txt")

    Returns:
        Dictionary with paths to generated report files
    """
    print("[*] Generating analysis reports...")

    # Calculate risk level
    risk_level = calculate_risk_level(static_results or {}, dynamic_results or {})

    # Generate output paths
    json_path = f"{output_prefix}.json"
    txt_path = f"{output_prefix}.txt"

    # Generate reports
    generate_json_report(static_results or {}, dynamic_results or {}, risk_level, json_path)
    print(f"[+] JSON report saved: {json_path}")

    generate_text_report(static_results or {}, dynamic_results or {}, risk_level, txt_path)
    print(f"[+] Text report saved: {txt_path}")

    # Print summary to console
    print_summary(static_results, dynamic_results, risk_level)

    return {
        "json_report": json_path,
        "text_report": txt_path,
        "risk_level": risk_level
    }


# For testing as standalone module
if __name__ == "__main__":
    # Example test data
    test_static = {
        "permissions": [
            {"permission": "android.permission.ACCESS_FINE_LOCATION", "risk_level": "HIGH"},
            {"permission": "android.permission.INTERNET", "risk_level": "LOW"}
        ],
        "sensitive_apis": [
            {"api": "getLastKnownLocation", "risk_level": "HIGH", "description": "Gets GPS location"}
        ],
        "network_apis": [
            {"api": "OkHttp", "risk_level": "MEDIUM", "description": "HTTP client"}
        ],
        "analysis_summary": {
            "total_permissions": 2,
            "high_risk_permissions": 1,
            "sensitive_apis_found": 1,
            "network_apis_found": 1
        }
    }

    test_dynamic = {
        "urls": ["https://api.example.com/location", "https://analytics.example.com/track"],
        "methods": ["POST", "GET"],
        "leaked_data_matches": [
            {"type": "gps_latitude", "value": "37.7749", "risk_level": "HIGH"}
        ],
        "tracking_domains": ["analytics.example.com"],
        "analysis_summary": {
            "total_flows": 10,
            "unique_hosts": 3,
            "tracking_domains_contacted": 1,
            "total_leaks_detected": 1,
            "high_risk_leaks": 1
        }
    }

    result = generate_report(test_static, test_dynamic, "test_report")
    print(f"\nGenerated reports: {result}")
