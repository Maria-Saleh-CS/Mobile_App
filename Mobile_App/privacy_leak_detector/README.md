# Mobile App Privacy Leakage Detector

A comprehensive tool for detecting privacy data leakage in Android mobile applications through static and dynamic analysis.

## Features

### Static Analysis
- **Permission Extraction**: Extracts and categorizes all permissions from AndroidManifest.xml
- **Sensitive API Detection**: Identifies usage of privacy-sensitive Android APIs:
  - Device identifiers: `getDeviceId()`, `getImei()`, `getSimSerialNumber()`
  - Location APIs: `getLastKnownLocation()`, `getLatitude()`, `getLongitude()`
  - Personal data: `getAccounts()`, `getContacts()`
- **Network API Detection**: Detects networking libraries that can transmit data:
  - `HttpURLConnection`, `OkHttp`, `Retrofit`, `Socket`, `WebView.loadUrl()`

### Dynamic Analysis
- **Traffic Log Parsing**: Parses mitmproxy JSON traffic logs
- **Data Leak Detection**: Identifies potential leakage of:
  - GPS coordinates (latitude/longitude)
  - Device identifiers (IMEI, Android ID, MAC address)
  - Email addresses
  - Phone numbers
  - Authentication tokens
- **Tracking Domain Detection**: Identifies connections to known analytics/tracking services

### Risk Assessment
- Combines static and dynamic findings
- Assigns overall risk level: **LOW**, **MEDIUM**, or **HIGH**
- Generates actionable security recommendations

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Setup

1. Clone or download this project:
```bash
cd privacy_leak_detector
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### GUI Mode (Recommended for beginners)

Launch the graphical interface:
```bash
python gui_detector.py
```

The GUI provides:
- File browsers for selecting APK and traffic files
- Folder selection for output reports
- Real-time analysis progress display
- Color-coded results with risk highlighting
- One-click sample traffic file creation

### CLI Mode

**Analyze APK only:**
```bash
python detector.py --apk sample.apk --out report
```

**Analyze traffic log only:**
```bash
python detector.py --traffic traffic.json --out report
```

**Full analysis (APK + traffic):**
```bash
python detector.py --apk sample.apk --traffic traffic.json --out report
```

**Create sample traffic file for testing:**
```bash
python detector.py --create-sample sample_traffic.json
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--apk FILE` | `-a` | Path to Android APK file |
| `--traffic FILE` | `-t` | Path to mitmproxy traffic log (.json) |
| `--out PREFIX` | `-o` | Output file prefix (default: privacy_report) |
| `--create-sample FILE` | | Create a sample traffic file |
| `--quiet` | `-q` | Suppress banner and status messages |
| `--version` | `-v` | Show version information |

## Output Files

The tool generates two report files:

1. **`<prefix>.json`** - Machine-readable JSON report containing:
   - Complete analysis data
   - Risk assessment with factors
   - All detected issues

2. **`<prefix>.txt`** - Human-readable text report containing:
   - Executive summary
   - Detailed findings organized by category
   - Security recommendations

## Example Output

### Console Output
```
╔══════════════════════════════════════════════════════════════════════╗
║         MOBILE APP PRIVACY LEAKAGE DETECTOR v1.0                     ║
╚══════════════════════════════════════════════════════════════════════╝

[*] Starting static analysis...
[*] Analyzing APK: sample.apk
[+] Found 15 permissions
[+] Found 3 sensitive APIs
[+] Found 2 network APIs
[+] Static analysis completed

[*] Starting dynamic analysis...
[*] Analyzing traffic log: traffic.json
[*] Parsed 50 HTTP flows
[+] Analyzed 50 flows
[+] Found 5 potential data leaks
[+] Detected 2 tracking domains
[+] Dynamic analysis completed

============================================================
                    PRIVACY ANALYSIS SUMMARY
============================================================

Overall Risk Level: HIGH

Static Analysis:
  - Permissions: 15 (4 high-risk)
  - Sensitive APIs: 3
  - Network APIs: 2

Dynamic Analysis:
  - HTTP Flows: 50
  - Data Leaks: 5 (3 high-risk)
  - Tracking Domains: 2

============================================================
```

### Sample JSON Report Structure
```json
{
  "report_metadata": {
    "generated_at": "2024-01-15T10:30:00",
    "tool_name": "Mobile App Privacy Leakage Detector",
    "version": "1.0.0"
  },
  "risk_assessment": {
    "overall_risk_level": "HIGH",
    "risk_factors": [
      "4 high-risk permissions requested",
      "3 sensitive APIs detected in code",
      "5 potential data leaks detected in traffic"
    ]
  },
  "static_analysis": {
    "permissions": [...],
    "sensitive_apis": [...],
    "network_apis": [...]
  },
  "dynamic_analysis": {
    "urls": [...],
    "leaked_data_matches": [...],
    "tracking_domains": [...]
  },
  "recommendations": [...]
}
```

## Capturing Traffic with mitmproxy

To capture traffic for dynamic analysis:

1. Install mitmproxy:
```bash
pip install mitmproxy
```

2. Start mitmproxy:
```bash
mitmproxy --save-stream-file traffic.mitm
```

3. Configure your Android device to use mitmproxy as HTTP proxy

4. Export traffic to JSON:
```bash
mitmdump -r traffic.mitm --set flow_detail=3 -w traffic.json
```

Or use mitmweb for a GUI interface:
```bash
mitmweb
```

## Extending Detection Rules

### Adding New Sensitive APIs

Edit `static_analyzer.py` and add to the `SENSITIVE_APIS` dictionary:

```python
SENSITIVE_APIS = {
    "myNewApi": {
        "class_pattern": r"Lcom/example/MyClass;",
        "method": "sensitiveMethod",
        "risk": "HIGH",
        "description": "Description of what this API does"
    },
    # ... existing APIs
}
```

### Adding New Leak Patterns

Edit `dynamic_analyzer.py` and add to the `LEAK_PATTERNS` dictionary:

```python
LEAK_PATTERNS = {
    "my_new_pattern": {
        "patterns": [
            r'my_regex_pattern_here',
        ],
        "risk": "HIGH",
        "description": "Description of what this pattern detects"
    },
    # ... existing patterns
}
```

### Adding New Tracking Domains

Edit `dynamic_analyzer.py` and add to the `TRACKING_DOMAINS` list:

```python
TRACKING_DOMAINS = [
    "new-tracker.com",
    "analytics.newservice.com",
    # ... existing domains
]
```

### Adding New Dangerous Permissions

Edit `static_analyzer.py` and add to the `DANGEROUS_PERMISSIONS` dictionary:

```python
DANGEROUS_PERMISSIONS = {
    "android.permission.NEW_PERMISSION": "HIGH",
    # ... existing permissions
}
```

## Project Structure

```
privacy_leak_detector/
├── gui_detector.py      # GUI application (Tkinter)
├── detector.py          # CLI entry point
├── static_analyzer.py   # APK static analysis module
├── dynamic_analyzer.py  # Traffic dynamic analysis module
├── report_generator.py  # Report generation module
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## Module APIs

### static_analyzer.py
```python
from static_analyzer import analyze_apk

results = analyze_apk("sample.apk")
# Returns: {
#   "permissions": [...],
#   "sensitive_apis": [...],
#   "network_apis": [...],
#   "app_info": {...},
#   "analysis_summary": {...}
# }
```

### dynamic_analyzer.py
```python
from dynamic_analyzer import analyze_traffic

results = analyze_traffic("traffic.json")
# Returns: {
#   "urls": [...],
#   "methods": [...],
#   "leaked_data_matches": [...],
#   "tracking_domains": [...],
#   "analysis_summary": {...}
# }
```

### report_generator.py
```python
from report_generator import generate_report

report_paths = generate_report(static_results, dynamic_results, "output_prefix")
# Returns: {
#   "json_report": "output_prefix.json",
#   "text_report": "output_prefix.txt",
#   "risk_level": "HIGH"
# }
```

## Offline Operation

This tool operates completely offline:
- No internet connection required
- No external API calls
- No data sent to third parties
- All analysis performed locally

## Limitations

- Static analysis may not detect obfuscated code
- Dynamic analysis requires pre-captured traffic
- Some sophisticated data exfiltration techniques may not be detected
- Encrypted payloads cannot be analyzed without proper keys

## Contributing

To extend or improve this tool:

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Submit a pull request

## License

This project is provided for educational purposes as part of a university project on mobile app privacy analysis.

## References

- [Androguard Documentation](https://androguard.readthedocs.io/)
- [mitmproxy Documentation](https://docs.mitmproxy.org/)
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security/)
- [Android Permissions](https://developer.android.com/guide/topics/permissions/overview)
