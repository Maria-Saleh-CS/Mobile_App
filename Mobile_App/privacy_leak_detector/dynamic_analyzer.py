#!/usr/bin/env python3
"""
Dynamic Analyzer Module for Mobile App Privacy Leakage Detection
Analyzes mitmproxy traffic logs for privacy data leakage.
"""

import os
import re
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs, unquote
import base64


# Regex patterns for detecting sensitive data in traffic
LEAK_PATTERNS = {
    # GPS Coordinates
    "gps_latitude": {
        "patterns": [
            r'["\']?lat(?:itude)?["\']?\s*[:=]\s*["\']?(-?\d{1,3}\.\d{4,})["\']?',
            r'lat(?:itude)?=(-?\d{1,3}\.\d{4,})',
            r'["\']?location["\']?\s*:\s*\{[^}]*["\']?lat(?:itude)?["\']?\s*:\s*(-?\d{1,3}\.\d{4,})',
        ],
        "risk": "HIGH",
        "description": "GPS latitude coordinate detected"
    },
    "gps_longitude": {
        "patterns": [
            r'["\']?lon(?:g(?:itude)?)?["\']?\s*[:=]\s*["\']?(-?\d{1,3}\.\d{4,})["\']?',
            r'lon(?:g(?:itude)?)?=(-?\d{1,3}\.\d{4,})',
            r'["\']?location["\']?\s*:\s*\{[^}]*["\']?lon(?:g(?:itude)?)?["\']?\s*:\s*(-?\d{1,3}\.\d{4,})',
        ],
        "risk": "HIGH",
        "description": "GPS longitude coordinate detected"
    },
    "gps_coordinates": {
        "patterns": [
            r'(-?\d{1,3}\.\d{4,})\s*,\s*(-?\d{1,3}\.\d{4,})',  # lat,lng format
            r'geo:(-?\d{1,3}\.\d{4,}),(-?\d{1,3}\.\d{4,})',
        ],
        "risk": "HIGH",
        "description": "GPS coordinates detected"
    },

    # Device Identifiers
    "device_id": {
        "patterns": [
            r'["\']?device[_-]?id["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{14,16})["\']?',
            r'["\']?deviceId["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{14,16})["\']?',
            r'device[_-]?id=([a-fA-F0-9]{14,16})',
        ],
        "risk": "HIGH",
        "description": "Device ID (IMEI/MEID) detected"
    },
    "android_id": {
        "patterns": [
            r'["\']?android[_-]?id["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{16})["\']?',
            r'android[_-]?id=([a-fA-F0-9]{16})',
        ],
        "risk": "HIGH",
        "description": "Android ID detected"
    },
    "imei": {
        "patterns": [
            r'["\']?imei["\']?\s*[:=]\s*["\']?(\d{15})["\']?',
            r'imei=(\d{15})',
        ],
        "risk": "HIGH",
        "description": "IMEI number detected"
    },
    "mac_address": {
        "patterns": [
            r'["\']?mac[_-]?(?:address)?["\']?\s*[:=]\s*["\']?([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}["\']?',
            r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}',
        ],
        "risk": "HIGH",
        "description": "MAC address detected"
    },

    # Personal Information
    "email": {
        "patterns": [
            r'["\']?email["\']?\s*[:=]\s*["\']?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']?',
            r'email=([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        ],
        "risk": "MEDIUM",
        "description": "Email address detected"
    },
    "phone_number": {
        "patterns": [
            r'["\']?phone[_-]?(?:number)?["\']?\s*[:=]\s*["\']?(\+?[\d\s\-\(\)]{10,})["\']?',
            r'phone=(\+?[\d\s\-\(\)]{10,})',
        ],
        "risk": "HIGH",
        "description": "Phone number detected"
    },

    # Authentication/Session Data
    "auth_token": {
        "patterns": [
            r'["\']?(?:auth[_-]?)?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
            r'["\']?bearer["\']?\s*[:=]?\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
            r'Authorization:\s*Bearer\s+([a-zA-Z0-9_\-\.]+)',
        ],
        "risk": "MEDIUM",
        "description": "Authentication token detected"
    },
    "session_id": {
        "patterns": [
            r'["\']?session[_-]?id["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
            r'JSESSIONID=([a-zA-Z0-9_\-]+)',
            r'PHPSESSID=([a-zA-Z0-9_\-]+)',
        ],
        "risk": "MEDIUM",
        "description": "Session ID detected"
    },

    # Advertising IDs
    "advertising_id": {
        "patterns": [
            r'["\']?(?:advertising|ad)[_-]?id["\']?\s*[:=]\s*["\']?([a-fA-F0-9\-]{36})["\']?',
            r'gaid=([a-fA-F0-9\-]{36})',
            r'idfa=([a-fA-F0-9\-]{36})',
        ],
        "risk": "MEDIUM",
        "description": "Advertising ID detected"
    },

    # SIM/Carrier Information
    "sim_serial": {
        "patterns": [
            r'["\']?sim[_-]?serial["\']?\s*[:=]\s*["\']?(\d{18,22})["\']?',
            r'iccid=(\d{18,22})',
        ],
        "risk": "HIGH",
        "description": "SIM serial number (ICCID) detected"
    },
    "imsi": {
        "patterns": [
            r'["\']?imsi["\']?\s*[:=]\s*["\']?(\d{15})["\']?',
            r'imsi=(\d{15})',
        ],
        "risk": "HIGH",
        "description": "IMSI (subscriber ID) detected"
    }
}

# Known tracking/analytics domains
TRACKING_DOMAINS = [
    "google-analytics.com",
    "googleadservices.com",
    "doubleclick.net",
    "facebook.com/tr",
    "analytics.facebook.com",
    "crashlytics.com",
    "flurry.com",
    "mixpanel.com",
    "segment.io",
    "segment.com",
    "amplitude.com",
    "appsflyer.com",
    "adjust.com",
    "branch.io",
    "firebase.google.com",
    "app-measurement.com",
    "mopub.com",
    "unity3d.com",
    "applovin.com",
    "chartboost.com",
    "vungle.com",
    "inmobi.com",
    "startapp.com",
    "tapjoy.com"
]


def parse_mitmproxy_json(log_path: str) -> List[Dict[str, Any]]:
    """
    Parse mitmproxy JSON export format.
    """
    flows = []

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()

            # Handle JSON array format
            if content.startswith('['):
                data = json.loads(content)
                for item in data:
                    flow = parse_flow_object(item)
                    if flow:
                        flows.append(flow)

            # Handle NDJSON (newline-delimited JSON) format
            else:
                for line in content.split('\n'):
                    line = line.strip()
                    if line:
                        try:
                            item = json.loads(line)
                            flow = parse_flow_object(item)
                            if flow:
                                flows.append(flow)
                        except json.JSONDecodeError:
                            continue

    except json.JSONDecodeError as e:
        print(f"Warning: JSON parsing error: {e}")
    except Exception as e:
        print(f"Warning: Error reading log file: {e}")

    return flows


def parse_flow_object(item: Dict) -> Optional[Dict[str, Any]]:
    """
    Parse a single flow object from mitmproxy export.
    """
    try:
        flow = {
            "url": "",
            "method": "",
            "host": "",
            "path": "",
            "request_headers": {},
            "request_body": "",
            "response_status": 0,
            "response_headers": {},
            "response_body": ""
        }

        # Handle mitmproxy dump format
        if "request" in item:
            req = item["request"]
            flow["method"] = req.get("method", "")
            flow["host"] = req.get("host", "")
            flow["path"] = req.get("path", "")
            flow["url"] = f"{req.get('scheme', 'https')}://{flow['host']}{flow['path']}"

            # Parse headers
            headers = req.get("headers", [])
            if isinstance(headers, list):
                flow["request_headers"] = {h[0]: h[1] for h in headers if len(h) >= 2}
            elif isinstance(headers, dict):
                flow["request_headers"] = headers

            # Get request body
            content = req.get("content", "")
            if content:
                if isinstance(content, bytes):
                    flow["request_body"] = content.decode('utf-8', errors='ignore')
                else:
                    flow["request_body"] = str(content)

        # Handle response
        if "response" in item:
            resp = item["response"]
            flow["response_status"] = resp.get("status_code", 0)

            headers = resp.get("headers", [])
            if isinstance(headers, list):
                flow["response_headers"] = {h[0]: h[1] for h in headers if len(h) >= 2}
            elif isinstance(headers, dict):
                flow["response_headers"] = headers

            content = resp.get("content", "")
            if content:
                if isinstance(content, bytes):
                    flow["response_body"] = content.decode('utf-8', errors='ignore')
                else:
                    flow["response_body"] = str(content)

        # Handle simplified format
        if "url" in item and not flow["url"]:
            flow["url"] = item["url"]
            parsed = urlparse(item["url"])
            flow["host"] = parsed.netloc
            flow["path"] = parsed.path
            flow["method"] = item.get("method", "GET")

        if flow["url"]:
            return flow

    except Exception as e:
        print(f"Warning: Error parsing flow: {e}")

    return None


def parse_custom_json(log_path: str) -> List[Dict[str, Any]]:
    """
    Parse custom JSON traffic log formats.
    Supports various common formats.
    """
    flows = []

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)

        # Handle array of requests
        if isinstance(data, list):
            for item in data:
                flow = {
                    "url": item.get("url", item.get("uri", "")),
                    "method": item.get("method", "GET"),
                    "host": item.get("host", ""),
                    "path": item.get("path", ""),
                    "request_headers": item.get("headers", item.get("request_headers", {})),
                    "request_body": item.get("body", item.get("request_body", item.get("data", ""))),
                    "response_status": item.get("status", item.get("status_code", 0)),
                    "response_headers": item.get("response_headers", {}),
                    "response_body": item.get("response", item.get("response_body", ""))
                }

                if flow["url"]:
                    if not flow["host"]:
                        parsed = urlparse(flow["url"])
                        flow["host"] = parsed.netloc
                        flow["path"] = parsed.path
                    flows.append(flow)

        # Handle object with requests array
        elif isinstance(data, dict):
            requests = data.get("requests", data.get("flows", data.get("traffic", [])))
            for item in requests:
                flow = {
                    "url": item.get("url", item.get("uri", "")),
                    "method": item.get("method", "GET"),
                    "host": item.get("host", ""),
                    "path": item.get("path", ""),
                    "request_headers": item.get("headers", {}),
                    "request_body": item.get("body", item.get("data", "")),
                    "response_status": item.get("status", 0),
                    "response_headers": item.get("response_headers", {}),
                    "response_body": item.get("response", "")
                }

                if flow["url"]:
                    if not flow["host"]:
                        parsed = urlparse(flow["url"])
                        flow["host"] = parsed.netloc
                        flow["path"] = parsed.path
                    flows.append(flow)

    except Exception as e:
        print(f"Warning: Custom JSON parsing error: {e}")

    return flows


def detect_leaks_in_text(text: str) -> List[Dict[str, Any]]:
    """
    Scan text for potential privacy data leaks.
    """
    leaks = []

    if not text:
        return leaks

    # Decode URL encoding
    try:
        decoded_text = unquote(text)
    except:
        decoded_text = text

    # Try to decode base64 content
    try:
        # Check if it looks like base64
        if re.match(r'^[A-Za-z0-9+/]+=*$', text.replace('\n', '').replace('\r', '')):
            decoded_b64 = base64.b64decode(text).decode('utf-8', errors='ignore')
            decoded_text += " " + decoded_b64
    except:
        pass

    for leak_type, leak_info in LEAK_PATTERNS.items():
        for pattern in leak_info["patterns"]:
            try:
                matches = re.findall(pattern, decoded_text, re.IGNORECASE)
                for match in matches:
                    # Handle tuple matches (multiple groups)
                    if isinstance(match, tuple):
                        match_value = ",".join(str(m) for m in match if m)
                    else:
                        match_value = str(match)

                    # Skip if match is too short or obviously invalid
                    if len(match_value) < 3:
                        continue

                    leaks.append({
                        "type": leak_type,
                        "value": match_value[:100],  # Truncate long values
                        "risk_level": leak_info["risk"],
                        "description": leak_info["description"]
                    })
            except re.error:
                continue

    # Remove duplicate leaks
    seen = set()
    unique_leaks = []
    for leak in leaks:
        key = (leak["type"], leak["value"])
        if key not in seen:
            seen.add(key)
            unique_leaks.append(leak)

    return unique_leaks


def analyze_flow(flow: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a single HTTP flow for privacy leaks.
    """
    result = {
        "url": flow["url"],
        "method": flow["method"],
        "host": flow["host"],
        "is_tracking_domain": False,
        "leaks_in_url": [],
        "leaks_in_headers": [],
        "leaks_in_body": [],
        "leaks_in_response": []
    }

    # Check if it's a known tracking domain
    host_lower = flow["host"].lower()
    for tracking_domain in TRACKING_DOMAINS:
        if tracking_domain in host_lower:
            result["is_tracking_domain"] = True
            break

    # Scan URL for leaks
    result["leaks_in_url"] = detect_leaks_in_text(flow["url"])

    # Scan request headers for leaks
    headers_text = " ".join(f"{k}={v}" for k, v in flow.get("request_headers", {}).items())
    result["leaks_in_headers"] = detect_leaks_in_text(headers_text)

    # Scan request body for leaks
    result["leaks_in_body"] = detect_leaks_in_text(flow.get("request_body", ""))

    # Scan response body for leaks (might reveal what server received)
    result["leaks_in_response"] = detect_leaks_in_text(flow.get("response_body", ""))

    return result


def analyze_traffic(log_path: str) -> Dict[str, Any]:
    """
    Main function to analyze traffic log file for privacy leaks.

    Args:
        log_path: Path to mitmproxy traffic log (.json or custom format)

    Returns:
        Dictionary containing:
        - urls: List of destination URLs
        - methods: List of HTTP methods used
        - leaked_data_matches: List of detected privacy leaks
        - tracking_domains: List of tracking/analytics domains contacted
        - analysis_summary: Summary statistics
    """
    # Validate input
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Traffic log file not found: {log_path}")

    print(f"[*] Analyzing traffic log: {log_path}")

    results = {
        "urls": [],
        "methods": [],
        "hosts": [],
        "leaked_data_matches": [],
        "tracking_domains": [],
        "flow_analysis": [],
        "analysis_summary": {}
    }

    # Parse the traffic log
    flows = []

    if log_path.lower().endswith('.json'):
        # Try mitmproxy format first
        flows = parse_mitmproxy_json(log_path)

        # Fall back to custom format if no flows found
        if not flows:
            flows = parse_custom_json(log_path)
    else:
        # Try to parse as JSON anyway
        flows = parse_mitmproxy_json(log_path)
        if not flows:
            flows = parse_custom_json(log_path)

    print(f"[*] Parsed {len(flows)} HTTP flows")

    if not flows:
        print("[!] No HTTP flows found in log file")
        results["analysis_summary"] = {
            "total_flows": 0,
            "unique_hosts": 0,
            "tracking_domains_contacted": 0,
            "total_leaks_detected": 0,
            "high_risk_leaks": 0,
            "medium_risk_leaks": 0
        }
        return results

    # Analyze each flow
    all_leaks = []
    methods_seen = set()
    hosts_seen = set()
    tracking_hosts = set()

    for flow in flows:
        results["urls"].append(flow["url"])
        methods_seen.add(flow["method"])
        hosts_seen.add(flow["host"])

        # Analyze flow for leaks
        flow_result = analyze_flow(flow)
        results["flow_analysis"].append(flow_result)

        if flow_result["is_tracking_domain"]:
            tracking_hosts.add(flow["host"])

        # Collect all leaks
        for leak in flow_result["leaks_in_url"]:
            leak["location"] = "URL"
            leak["url"] = flow["url"]
            all_leaks.append(leak)

        for leak in flow_result["leaks_in_headers"]:
            leak["location"] = "Request Headers"
            leak["url"] = flow["url"]
            all_leaks.append(leak)

        for leak in flow_result["leaks_in_body"]:
            leak["location"] = "Request Body"
            leak["url"] = flow["url"]
            all_leaks.append(leak)

    results["methods"] = list(methods_seen)
    results["hosts"] = list(hosts_seen)
    results["tracking_domains"] = list(tracking_hosts)
    results["leaked_data_matches"] = all_leaks

    # Generate summary
    high_risk = sum(1 for l in all_leaks if l.get("risk_level") == "HIGH")
    medium_risk = sum(1 for l in all_leaks if l.get("risk_level") == "MEDIUM")

    results["analysis_summary"] = {
        "total_flows": len(flows),
        "unique_hosts": len(hosts_seen),
        "tracking_domains_contacted": len(tracking_hosts),
        "total_leaks_detected": len(all_leaks),
        "high_risk_leaks": high_risk,
        "medium_risk_leaks": medium_risk,
        "leak_types_found": list(set(l["type"] for l in all_leaks))
    }

    print(f"[+] Analyzed {len(flows)} flows")
    print(f"[+] Found {len(all_leaks)} potential data leaks")
    print(f"[+] Detected {len(tracking_hosts)} tracking domains")

    return results


# For testing as standalone module
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dynamic_analyzer.py <traffic_log_file>")
        sys.exit(1)

    log_file = sys.argv[1]

    try:
        results = analyze_traffic(log_file)
        print("\n" + "="*60)
        print("DYNAMIC ANALYSIS RESULTS")
        print("="*60)
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
