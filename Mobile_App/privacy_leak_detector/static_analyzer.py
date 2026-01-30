#!/usr/bin/env python3
"""
Static Analyzer Module for Mobile App Privacy Leakage Detection
Analyzes Android APK files for permissions and sensitive API usage.
"""

import os
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional

# Try to import androguard components
try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    ANDROGUARD_AVAILABLE = True
except ImportError:
    try:
        from androguard.core.bytecodes.apk import APK
        from androguard.core.bytecodes.dvm import DalvikVMFormat
        ANDROGUARD_AVAILABLE = True
    except ImportError:
        ANDROGUARD_AVAILABLE = False


# Sensitive APIs that may leak private data
SENSITIVE_APIS = {
    # Device identifiers
    "getDeviceId": {
        "class_pattern": r"Landroid/telephony/TelephonyManager;",
        "method": "getDeviceId",
        "risk": "HIGH",
        "description": "Retrieves unique device identifier (IMEI/MEID)"
    },
    "getImei": {
        "class_pattern": r"Landroid/telephony/TelephonyManager;",
        "method": "getImei",
        "risk": "HIGH",
        "description": "Retrieves device IMEI number"
    },
    "getSimSerialNumber": {
        "class_pattern": r"Landroid/telephony/TelephonyManager;",
        "method": "getSimSerialNumber",
        "risk": "HIGH",
        "description": "Retrieves SIM card serial number"
    },
    # Location APIs
    "getLastKnownLocation": {
        "class_pattern": r"Landroid/location/LocationManager;",
        "method": "getLastKnownLocation",
        "risk": "HIGH",
        "description": "Retrieves last known GPS location"
    },
    "getLatitude": {
        "class_pattern": r"Landroid/location/Location;",
        "method": "getLatitude",
        "risk": "HIGH",
        "description": "Retrieves GPS latitude coordinate"
    },
    "getLongitude": {
        "class_pattern": r"Landroid/location/Location;",
        "method": "getLongitude",
        "risk": "HIGH",
        "description": "Retrieves GPS longitude coordinate"
    },
    # Contacts and accounts
    "getAccounts": {
        "class_pattern": r"Landroid/accounts/AccountManager;",
        "method": "getAccounts",
        "risk": "MEDIUM",
        "description": "Retrieves user accounts on device"
    },
    # Additional sensitive APIs
    "getSubscriberId": {
        "class_pattern": r"Landroid/telephony/TelephonyManager;",
        "method": "getSubscriberId",
        "risk": "HIGH",
        "description": "Retrieves IMSI (subscriber identifier)"
    },
    "getMacAddress": {
        "class_pattern": r"Landroid/net/wifi/WifiInfo;",
        "method": "getMacAddress",
        "risk": "HIGH",
        "description": "Retrieves device MAC address"
    },
    "getLine1Number": {
        "class_pattern": r"Landroid/telephony/TelephonyManager;",
        "method": "getLine1Number",
        "risk": "HIGH",
        "description": "Retrieves phone number"
    },
    "getAndroidId": {
        "class_pattern": r"Landroid/provider/Settings\$Secure;",
        "method": "getString",
        "risk": "MEDIUM",
        "description": "May retrieve Android ID"
    }
}

# Network APIs that can transmit data
NETWORK_APIS = {
    "HttpURLConnection": {
        "class_pattern": r"Ljava/net/HttpURLConnection;|Ljavax/net/ssl/HttpsURLConnection;",
        "risk": "MEDIUM",
        "description": "Standard HTTP/HTTPS connection"
    },
    "OkHttp": {
        "class_pattern": r"Lokhttp3/|Lcom/squareup/okhttp/",
        "risk": "MEDIUM",
        "description": "OkHttp networking library"
    },
    "Retrofit": {
        "class_pattern": r"Lretrofit2/|Lretrofit/",
        "risk": "MEDIUM",
        "description": "Retrofit HTTP client"
    },
    "Socket": {
        "class_pattern": r"Ljava/net/Socket;|Ljava/net/DatagramSocket;",
        "risk": "MEDIUM",
        "description": "Raw socket connection"
    },
    "WebView.loadUrl": {
        "class_pattern": r"Landroid/webkit/WebView;",
        "method": "loadUrl",
        "risk": "MEDIUM",
        "description": "WebView URL loading"
    },
    "Volley": {
        "class_pattern": r"Lcom/android/volley/",
        "risk": "MEDIUM",
        "description": "Volley networking library"
    },
    "Apache HTTP": {
        "class_pattern": r"Lorg/apache/http/",
        "risk": "MEDIUM",
        "description": "Apache HTTP client (deprecated)"
    }
}

# Dangerous permissions to flag
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS": "HIGH",
    "android.permission.WRITE_CONTACTS": "HIGH",
    "android.permission.GET_ACCOUNTS": "MEDIUM",
    "android.permission.ACCESS_FINE_LOCATION": "HIGH",
    "android.permission.ACCESS_COARSE_LOCATION": "MEDIUM",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "HIGH",
    "android.permission.READ_PHONE_STATE": "HIGH",
    "android.permission.READ_PHONE_NUMBERS": "HIGH",
    "android.permission.CALL_PHONE": "MEDIUM",
    "android.permission.READ_CALL_LOG": "HIGH",
    "android.permission.WRITE_CALL_LOG": "HIGH",
    "android.permission.READ_CALENDAR": "MEDIUM",
    "android.permission.WRITE_CALENDAR": "MEDIUM",
    "android.permission.READ_SMS": "HIGH",
    "android.permission.SEND_SMS": "HIGH",
    "android.permission.RECEIVE_SMS": "HIGH",
    "android.permission.CAMERA": "MEDIUM",
    "android.permission.RECORD_AUDIO": "HIGH",
    "android.permission.READ_EXTERNAL_STORAGE": "MEDIUM",
    "android.permission.WRITE_EXTERNAL_STORAGE": "MEDIUM",
    "android.permission.INTERNET": "LOW",
    "android.permission.ACCESS_NETWORK_STATE": "LOW",
    "android.permission.ACCESS_WIFI_STATE": "LOW",
    "android.permission.BLUETOOTH": "LOW",
    "android.permission.BLUETOOTH_ADMIN": "MEDIUM",
    "android.permission.NFC": "LOW",
    "android.permission.BODY_SENSORS": "MEDIUM",
    "android.permission.ACTIVITY_RECOGNITION": "MEDIUM"
}


def extract_manifest_from_apk(apk_path: str) -> Optional[str]:
    """
    Extract AndroidManifest.xml content from APK using zipfile.
    This is a fallback method when androguard fails.
    """
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            # AndroidManifest.xml in APK is in binary XML format
            # This won't work directly, but we try to read it
            if 'AndroidManifest.xml' in apk_zip.namelist():
                return apk_zip.read('AndroidManifest.xml')
    except Exception:
        pass
    return None


def analyze_permissions_manual(apk_path: str) -> List[Dict[str, Any]]:
    """
    Fallback method to extract permissions when androguard is not available.
    Searches for permission strings in the APK.
    """
    permissions = []
    permission_pattern = re.compile(rb'android\.permission\.[A-Z_]+')

    try:
        with open(apk_path, 'rb') as f:
            content = f.read()
            matches = permission_pattern.findall(content)
            seen = set()
            for match in matches:
                perm = match.decode('utf-8', errors='ignore')
                if perm not in seen:
                    seen.add(perm)
                    risk = DANGEROUS_PERMISSIONS.get(perm, "LOW")
                    permissions.append({
                        "permission": perm,
                        "risk_level": risk,
                        "description": get_permission_description(perm)
                    })
    except Exception as e:
        print(f"Warning: Manual permission extraction failed: {e}")

    return permissions


def get_permission_description(permission: str) -> str:
    """Get human-readable description for a permission."""
    descriptions = {
        "android.permission.READ_CONTACTS": "Read user's contacts",
        "android.permission.WRITE_CONTACTS": "Modify user's contacts",
        "android.permission.GET_ACCOUNTS": "Access accounts on device",
        "android.permission.ACCESS_FINE_LOCATION": "Access precise GPS location",
        "android.permission.ACCESS_COARSE_LOCATION": "Access approximate location",
        "android.permission.ACCESS_BACKGROUND_LOCATION": "Access location in background",
        "android.permission.READ_PHONE_STATE": "Read phone state and identity",
        "android.permission.READ_PHONE_NUMBERS": "Read phone numbers",
        "android.permission.CALL_PHONE": "Make phone calls",
        "android.permission.READ_CALL_LOG": "Read call history",
        "android.permission.WRITE_CALL_LOG": "Modify call history",
        "android.permission.READ_CALENDAR": "Read calendar events",
        "android.permission.WRITE_CALENDAR": "Modify calendar events",
        "android.permission.READ_SMS": "Read SMS messages",
        "android.permission.SEND_SMS": "Send SMS messages",
        "android.permission.RECEIVE_SMS": "Receive SMS messages",
        "android.permission.CAMERA": "Access device camera",
        "android.permission.RECORD_AUDIO": "Record audio/microphone",
        "android.permission.READ_EXTERNAL_STORAGE": "Read external storage",
        "android.permission.WRITE_EXTERNAL_STORAGE": "Write to external storage",
        "android.permission.INTERNET": "Access internet",
        "android.permission.ACCESS_NETWORK_STATE": "View network state",
        "android.permission.ACCESS_WIFI_STATE": "View WiFi state",
        "android.permission.BLUETOOTH": "Access Bluetooth",
        "android.permission.BLUETOOTH_ADMIN": "Administer Bluetooth",
        "android.permission.NFC": "Access NFC",
        "android.permission.BODY_SENSORS": "Access body sensors",
        "android.permission.ACTIVITY_RECOGNITION": "Recognize physical activity"
    }
    return descriptions.get(permission, "Unknown permission")


def search_dex_for_apis(apk_path: str) -> tuple:
    """
    Search DEX files in APK for sensitive and network API usage.
    Returns (sensitive_apis, network_apis)
    """
    sensitive_found = []
    network_found = []

    try:
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            # Find all DEX files
            dex_files = [f for f in apk_zip.namelist() if f.endswith('.dex')]

            for dex_name in dex_files:
                dex_content = apk_zip.read(dex_name)

                # Search for sensitive APIs
                for api_name, api_info in SENSITIVE_APIS.items():
                    pattern = api_info["class_pattern"].encode()
                    method = api_info.get("method", "").encode()

                    if re.search(pattern, dex_content):
                        if method:
                            if method in dex_content:
                                sensitive_found.append({
                                    "api": api_name,
                                    "risk_level": api_info["risk"],
                                    "description": api_info["description"],
                                    "found_in": dex_name
                                })
                        else:
                            sensitive_found.append({
                                "api": api_name,
                                "risk_level": api_info["risk"],
                                "description": api_info["description"],
                                "found_in": dex_name
                            })

                # Search for network APIs
                for api_name, api_info in NETWORK_APIS.items():
                    pattern = api_info["class_pattern"].encode()
                    if re.search(pattern, dex_content):
                        method = api_info.get("method", "")
                        if method:
                            if method.encode() in dex_content:
                                network_found.append({
                                    "api": api_name,
                                    "risk_level": api_info["risk"],
                                    "description": api_info["description"],
                                    "found_in": dex_name
                                })
                        else:
                            network_found.append({
                                "api": api_name,
                                "risk_level": api_info["risk"],
                                "description": api_info["description"],
                                "found_in": dex_name
                            })

    except Exception as e:
        print(f"Warning: DEX analysis error: {e}")

    # Remove duplicates
    sensitive_found = _deduplicate_findings(sensitive_found)
    network_found = _deduplicate_findings(network_found)

    return sensitive_found, network_found


def _deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """Remove duplicate findings based on API name."""
    seen = set()
    unique = []
    for finding in findings:
        if finding["api"] not in seen:
            seen.add(finding["api"])
            unique.append(finding)
    return unique


def analyze_with_androguard(apk_path: str) -> Dict[str, Any]:
    """
    Analyze APK using Androguard library for detailed analysis.
    """
    results = {
        "permissions": [],
        "sensitive_apis": [],
        "network_apis": [],
        "app_info": {}
    }

    try:
        apk = APK(apk_path)

        # Get app info
        results["app_info"] = {
            "package_name": apk.get_package(),
            "app_name": apk.get_app_name(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version()
        }

        # Get permissions
        permissions = apk.get_permissions()
        for perm in permissions:
            risk = DANGEROUS_PERMISSIONS.get(perm, "LOW")
            results["permissions"].append({
                "permission": perm,
                "risk_level": risk,
                "description": get_permission_description(perm)
            })

        # Analyze DEX for API usage
        sensitive, network = search_dex_for_apis(apk_path)
        results["sensitive_apis"] = sensitive
        results["network_apis"] = network

    except Exception as e:
        print(f"Androguard analysis error: {e}")
        # Fall back to manual analysis
        results["permissions"] = analyze_permissions_manual(apk_path)
        sensitive, network = search_dex_for_apis(apk_path)
        results["sensitive_apis"] = sensitive
        results["network_apis"] = network

    return results


def analyze_apk(apk_path: str) -> Dict[str, Any]:
    """
    Main function to analyze an Android APK file.

    Args:
        apk_path: Path to the APK file

    Returns:
        Dictionary containing:
        - permissions: List of requested permissions with risk levels
        - sensitive_apis: List of sensitive APIs found
        - network_apis: List of networking APIs found
        - app_info: Basic app information (if available)
    """
    # Validate input
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    if not apk_path.lower().endswith('.apk'):
        raise ValueError("File must be an APK file")

    print(f"[*] Analyzing APK: {apk_path}")

    results = {
        "permissions": [],
        "sensitive_apis": [],
        "network_apis": [],
        "app_info": {},
        "analysis_summary": {}
    }

    # Try androguard first, fall back to manual analysis
    if ANDROGUARD_AVAILABLE:
        print("[*] Using Androguard for analysis...")
        results = analyze_with_androguard(apk_path)
    else:
        print("[!] Androguard not available, using fallback analysis...")
        results["permissions"] = analyze_permissions_manual(apk_path)
        sensitive, network = search_dex_for_apis(apk_path)
        results["sensitive_apis"] = sensitive
        results["network_apis"] = network

    # Generate analysis summary
    high_risk_perms = sum(1 for p in results["permissions"] if p.get("risk_level") == "HIGH")
    high_risk_apis = sum(1 for a in results["sensitive_apis"] if a.get("risk_level") == "HIGH")

    results["analysis_summary"] = {
        "total_permissions": len(results["permissions"]),
        "high_risk_permissions": high_risk_perms,
        "sensitive_apis_found": len(results["sensitive_apis"]),
        "network_apis_found": len(results["network_apis"]),
        "has_internet_permission": any(
            "INTERNET" in p.get("permission", "")
            for p in results["permissions"]
        ),
        "has_location_permission": any(
            "LOCATION" in p.get("permission", "")
            for p in results["permissions"]
        ),
        "has_phone_state_permission": any(
            "PHONE_STATE" in p.get("permission", "")
            for p in results["permissions"]
        )
    }

    print(f"[+] Found {len(results['permissions'])} permissions")
    print(f"[+] Found {len(results['sensitive_apis'])} sensitive APIs")
    print(f"[+] Found {len(results['network_apis'])} network APIs")

    return results


# For testing as standalone module
if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python static_analyzer.py <apk_file>")
        sys.exit(1)

    apk_file = sys.argv[1]

    try:
        results = analyze_apk(apk_file)
        print("\n" + "="*60)
        print("STATIC ANALYSIS RESULTS")
        print("="*60)
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
