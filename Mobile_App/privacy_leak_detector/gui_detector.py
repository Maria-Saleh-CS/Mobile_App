#!/usr/bin/env python3
"""
Mobile App Privacy Leakage Detector - GUI Version
A user-friendly Tkinter interface for the privacy analysis tool.

This script wraps the existing CLI detector and provides:
- File selection dialogs for APK and traffic files
- Folder selection for output reports
- Real-time analysis results display with full details
- Color-coded output matching terminal experience
- Error handling with user-friendly messages

Usage:
    python gui_detector.py

Requirements:
    - Python 3.7+
    - tkinter (included with Python on Mac)
    - All dependencies from requirements.txt
"""

import os
import sys
import threading
import queue
from datetime import datetime
from typing import Optional, Dict, Any, List

# ==============================================================================
# Tkinter imports - these come with Python on Mac
# ==============================================================================
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

# ==============================================================================
# Import analysis modules from the existing CLI tool
# ==============================================================================
from static_analyzer import analyze_apk
from dynamic_analyzer import analyze_traffic
from report_generator import generate_report, calculate_risk_level


class PrivacyDetectorGUI:
    """
    Main GUI application class for the Privacy Leakage Detector.

    This class creates and manages the Tkinter window with all UI components
    and handles the analysis workflow with detailed output display.
    """

    def __init__(self, root: tk.Tk):
        """
        Initialize the GUI application.

        Args:
            root: The main Tkinter window (Tk instance)
        """
        self.root = root
        self.root.title("Mobile App Privacy Leakage Detector")

        # Set minimum window size for usability
        self.root.minsize(900, 700)

        # Configure the window to be resizable
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # ==================================================================
        # Instance variables to store user selections
        # ==================================================================
        self.apk_path = tk.StringVar()       # Path to selected APK file
        self.traffic_path = tk.StringVar()   # Path to selected traffic JSON
        self.output_folder = tk.StringVar()  # Path to output folder

        # Queue for thread-safe communication between analysis thread and GUI
        self.message_queue = queue.Queue()

        # Flag to track if analysis is running
        self.analysis_running = False

        # Build the GUI components
        self._create_widgets()

        # Start the queue polling for thread-safe updates
        self._poll_queue()

    def _create_widgets(self):
        """
        Create all GUI widgets and layout.

        The layout consists of:
        - Header with title
        - File selection section (APK, Traffic, Output)
        - Control buttons (Run Analysis, Clear)
        - Results display area (scrolling text)
        - Status bar at bottom
        """
        # ==================================================================
        # Main container frame with padding
        # ==================================================================
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(1, weight=1)  # Make middle column expandable
        main_frame.rowconfigure(6, weight=1)     # Make results area expandable

        # ==================================================================
        # HEADER SECTION - Title and description
        # ==================================================================
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 15))

        # Application title
        title_label = ttk.Label(
            header_frame,
            text="Mobile App Privacy Leakage Detector",
            font=("Helvetica", 18, "bold")
        )
        title_label.pack()

        # Subtitle/description
        subtitle_label = ttk.Label(
            header_frame,
            text="Static + Dynamic Analysis Tool for Android Applications",
            font=("Helvetica", 11)
        )
        subtitle_label.pack()

        # ==================================================================
        # FILE SELECTION SECTION
        # ==================================================================

        # --- APK File Selection (Row 1) ---
        apk_label = ttk.Label(main_frame, text="APK File:", font=("Helvetica", 11))
        apk_label.grid(row=1, column=0, sticky="w", pady=5)

        # Entry field showing selected APK path
        self.apk_entry = ttk.Entry(
            main_frame,
            textvariable=self.apk_path,
            width=60,
            state="readonly"  # Read-only to prevent manual editing
        )
        self.apk_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        # Browse button for APK selection
        apk_button = ttk.Button(
            main_frame,
            text="Browse...",
            command=self._browse_apk
        )
        apk_button.grid(row=1, column=2, pady=5)

        # --- Traffic File Selection (Row 2) ---
        traffic_label = ttk.Label(main_frame, text="Traffic Log:", font=("Helvetica", 11))
        traffic_label.grid(row=2, column=0, sticky="w", pady=5)

        # Entry field showing selected traffic file path
        self.traffic_entry = ttk.Entry(
            main_frame,
            textvariable=self.traffic_path,
            width=60,
            state="readonly"
        )
        self.traffic_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

        # Browse button for traffic file selection
        traffic_button = ttk.Button(
            main_frame,
            text="Browse...",
            command=self._browse_traffic
        )
        traffic_button.grid(row=2, column=2, pady=5)

        # --- Output Folder Selection (Row 3) ---
        output_label = ttk.Label(main_frame, text="Output Folder:", font=("Helvetica", 11))
        output_label.grid(row=3, column=0, sticky="w", pady=5)

        # Entry field showing selected output folder
        self.output_entry = ttk.Entry(
            main_frame,
            textvariable=self.output_folder,
            width=60,
            state="readonly"
        )
        self.output_entry.grid(row=3, column=1, sticky="ew", padx=5, pady=5)

        # Browse button for output folder selection
        output_button = ttk.Button(
            main_frame,
            text="Browse...",
            command=self._browse_output
        )
        output_button.grid(row=3, column=2, pady=5)

        # ==================================================================
        # CONTROL BUTTONS SECTION (Row 4)
        # ==================================================================
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=15)

        # Run Analysis button - main action button
        self.run_button = ttk.Button(
            button_frame,
            text="Run Analysis",
            command=self._run_analysis,
            style="Accent.TButton"
        )
        self.run_button.pack(side="left", padx=5)

        # Clear button - resets all selections and output
        clear_button = ttk.Button(
            button_frame,
            text="Clear All",
            command=self._clear_all
        )
        clear_button.pack(side="left", padx=5)

        # Create sample traffic file button - for testing
        sample_button = ttk.Button(
            button_frame,
            text="Create Sample Traffic",
            command=self._create_sample_traffic
        )
        sample_button.pack(side="left", padx=5)

        # ==================================================================
        # RESULTS DISPLAY SECTION (Row 5)
        # ==================================================================
        results_label = ttk.Label(
            main_frame,
            text="Analysis Results:",
            font=("Helvetica", 11, "bold")
        )
        results_label.grid(row=5, column=0, columnspan=3, sticky="w", pady=(10, 5))

        # Scrolling text area for displaying analysis results
        # This uses a monospace font for better formatting of results
        self.results_text = ScrolledText(
            main_frame,
            wrap=tk.WORD,
            width=100,
            height=25,
            font=("Courier", 11),
            state="disabled",  # Read-only initially
            bg="#1a1a2e",      # Dark blue background for better readability
            fg="#eaeaea",      # Light gray text
            insertbackground="#ffffff",
            selectbackground="#4a4a6a",
            padx=10,
            pady=10
        )
        self.results_text.grid(
            row=6, column=0, columnspan=3,
            sticky="nsew", pady=5
        )

        # Configure text tags for colored output
        self._configure_text_tags()

        # ==================================================================
        # STATUS BAR (Row 7)
        # ==================================================================
        self.status_var = tk.StringVar(value="Ready. Select files and click 'Run Analysis'.")
        status_bar = ttk.Label(
            main_frame,
            textvariable=self.status_var,
            relief="sunken",
            anchor="w",
            padding=(5, 2)
        )
        status_bar.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(5, 0))

        # ==================================================================
        # PROGRESS BAR (Row 8) - Shows during analysis
        # ==================================================================
        self.progress = ttk.Progressbar(
            main_frame,
            mode="indeterminate",
            length=300
        )
        self.progress.grid(row=8, column=0, columnspan=3, sticky="ew", pady=5)
        self.progress.grid_remove()  # Hidden by default

    def _configure_text_tags(self):
        """
        Configure text tags for colored output in the results area.

        Tags allow different colors for:
        - Headers (cyan)
        - Success messages (green)
        - Warnings (yellow/orange)
        - Errors (red)
        - Risk levels (color-coded)
        - Various text styles
        """
        # Main header styles
        self.results_text.tag_configure("header", foreground="#00bcd4", font=("Courier", 12, "bold"))
        self.results_text.tag_configure("subheader", foreground="#00bcd4", font=("Courier", 11, "bold"))

        # Status message styles
        self.results_text.tag_configure("success", foreground="#4caf50")
        self.results_text.tag_configure("warning", foreground="#ff9800")
        self.results_text.tag_configure("error", foreground="#f44336")
        self.results_text.tag_configure("info", foreground="#64b5f6")

        # Risk level styles - bold and larger for emphasis
        self.results_text.tag_configure("risk_high", foreground="#ff5252", font=("Courier", 14, "bold"))
        self.results_text.tag_configure("risk_medium", foreground="#ffab40", font=("Courier", 14, "bold"))
        self.results_text.tag_configure("risk_low", foreground="#69f0ae", font=("Courier", 14, "bold"))

        # Permission risk level styles
        self.results_text.tag_configure("perm_high", foreground="#ff5252")
        self.results_text.tag_configure("perm_medium", foreground="#ffab40")
        self.results_text.tag_configure("perm_low", foreground="#69f0ae")

        # Separators and formatting
        self.results_text.tag_configure("separator", foreground="#5c5c8a")
        self.results_text.tag_configure("dim", foreground="#888888")

        # Data display styles
        self.results_text.tag_configure("data_label", foreground="#b0bec5")
        self.results_text.tag_configure("data_value", foreground="#ffffff")
        self.results_text.tag_configure("url", foreground="#81d4fa")
        self.results_text.tag_configure("leak_value", foreground="#ffab91")

    def _browse_apk(self):
        """
        Open a file dialog to select an APK file.

        Only .apk files are shown in the dialog to prevent user errors.
        """
        filepath = filedialog.askopenfilename(
            title="Select Android APK File",
            filetypes=[
                ("Android APK", "*.apk"),
                ("All files", "*.*")
            ]
        )
        if filepath:
            self.apk_path.set(filepath)
            self._log_message(f"Selected APK: {os.path.basename(filepath)}", "info")

    def _browse_traffic(self):
        """
        Open a file dialog to select a traffic log file.

        Accepts .json files (mitmproxy export format).
        """
        filepath = filedialog.askopenfilename(
            title="Select Traffic Log File",
            filetypes=[
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        if filepath:
            self.traffic_path.set(filepath)
            self._log_message(f"Selected Traffic Log: {os.path.basename(filepath)}", "info")

    def _browse_output(self):
        """
        Open a folder dialog to select the output directory.

        Reports will be saved to this folder.
        """
        folder = filedialog.askdirectory(
            title="Select Output Folder"
        )
        if folder:
            self.output_folder.set(folder)
            self._log_message(f"Output folder: {folder}", "info")

    def _clear_all(self):
        """
        Reset all selections and clear the results display.
        """
        self.apk_path.set("")
        self.traffic_path.set("")
        self.output_folder.set("")

        # Clear the results text area
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", tk.END)
        self.results_text.configure(state="disabled")

        self.status_var.set("Ready. Select files and click 'Run Analysis'.")

    def _create_sample_traffic(self):
        """
        Create a sample traffic log file for testing purposes.

        Opens a save dialog and creates a sample JSON file with
        example traffic data including some privacy leaks.
        """
        filepath = filedialog.asksaveasfilename(
            title="Save Sample Traffic File",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfilename="sample_traffic.json"
        )

        if filepath:
            import json

            # Sample traffic data with intentional "leaks" for testing
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
                        "path": "/collect?v=1&tid=UA-123456&cid=device123&latitude=40.7128&longitude=-74.0060",
                        "headers": [],
                        "content": ""
                    },
                    "response": {
                        "status_code": 200,
                        "headers": [],
                        "content": ""
                    }
                },
                {
                    "request": {
                        "method": "POST",
                        "scheme": "https",
                        "host": "crashlytics.com",
                        "path": "/api/v1/crash",
                        "headers": [["Content-Type", "application/json"]],
                        "content": '{"imei":"123456789012345","android_id":"abcdef1234567890"}'
                    },
                    "response": {
                        "status_code": 200,
                        "headers": [],
                        "content": ""
                    }
                },
                {
                    "request": {
                        "method": "POST",
                        "scheme": "https",
                        "host": "api.mixpanel.com",
                        "path": "/track",
                        "headers": [["Content-Type", "application/json"]],
                        "content": '{"event":"user_action","properties":{"phone":"+1-555-123-4567","mac_address":"AA:BB:CC:DD:EE:FF"}}'
                    },
                    "response": {
                        "status_code": 200,
                        "headers": [],
                        "content": ""
                    }
                }
            ]

            try:
                with open(filepath, 'w') as f:
                    json.dump(sample_traffic, f, indent=2)

                self._log_message(f"Created sample traffic file: {filepath}", "success")
                self.traffic_path.set(filepath)

            except Exception as e:
                self._log_message(f"Failed to create sample file: {e}", "error")

    def _log_message(self, message: str, tag: str = "info"):
        """
        Add a message to the results text area with optional formatting.

        Args:
            message: The text to display
            tag: The formatting tag (info, success, warning, error, header, etc.)
        """
        # Enable editing temporarily
        self.results_text.configure(state="normal")

        # Insert the message with appropriate tag
        if tag in ("header", "subheader"):
            self.results_text.insert(tk.END, f"{message}\n", tag)
        elif tag == "separator":
            self.results_text.insert(tk.END, f"{message}\n", tag)
        elif tag == "raw":
            # Raw text without any prefix
            self.results_text.insert(tk.END, f"{message}\n")
        elif tag.startswith("risk_") or tag.startswith("perm_"):
            # Risk levels without timestamp
            self.results_text.insert(tk.END, f"{message}\n", tag)
        else:
            # Add timestamp for status messages
            timestamp = datetime.now().strftime("%H:%M:%S")
            prefix = {
                "info": "[*]",
                "success": "[+]",
                "warning": "[!]",
                "error": "[-]"
            }.get(tag, "[*]")
            self.results_text.insert(tk.END, f"[{timestamp}] {prefix} {message}\n", tag)

        # Auto-scroll to the end to show latest message
        self.results_text.see(tk.END)

        # Disable editing again
        self.results_text.configure(state="disabled")

        # Force update to ensure smooth scrolling
        self.results_text.update_idletasks()

    def _log_raw(self, message: str, tag: str = "info"):
        """
        Add raw text without timestamp prefix.

        Args:
            message: The text to display
            tag: The formatting tag
        """
        self.results_text.configure(state="normal")
        self.results_text.insert(tk.END, f"{message}\n", tag)
        self.results_text.see(tk.END)
        self.results_text.configure(state="disabled")
        self.results_text.update_idletasks()

    def _queue_message(self, message: str, tag: str = "info"):
        """
        Thread-safe method to queue a message for display.

        This is called from the analysis thread to safely update the GUI.

        Args:
            message: The text to display
            tag: The formatting tag
        """
        self.message_queue.put(("log", message, tag))

    def _queue_raw(self, message: str, tag: str = "info"):
        """
        Thread-safe method to queue raw text for display.

        Args:
            message: The text to display
            tag: The formatting tag
        """
        self.message_queue.put(("raw", message, tag))

    def _poll_queue(self):
        """
        Check the message queue and display any pending messages.

        This runs periodically on the main thread to safely update the GUI
        with messages from the analysis thread.
        """
        try:
            while True:
                item = self.message_queue.get_nowait()
                if item[0] == "log":
                    _, message, tag = item
                    self._log_message(message, tag)
                elif item[0] == "raw":
                    _, message, tag = item
                    self._log_raw(message, tag)
        except queue.Empty:
            pass

        # Schedule the next poll (every 50ms for smoother updates)
        self.root.after(50, self._poll_queue)

    def _validate_inputs(self) -> bool:
        """
        Validate user inputs before running analysis.

        Returns:
            True if inputs are valid, False otherwise
        """
        apk = self.apk_path.get()
        traffic = self.traffic_path.get()
        output = self.output_folder.get()

        # Check if at least one input file is selected
        if not apk and not traffic:
            messagebox.showerror(
                "Input Required",
                "Please select at least one input file:\n"
                "- An APK file for static analysis, or\n"
                "- A traffic log file for dynamic analysis"
            )
            return False

        # Validate APK file if selected
        if apk:
            if not os.path.exists(apk):
                messagebox.showerror("File Not Found", f"APK file not found:\n{apk}")
                return False
            if not apk.lower().endswith('.apk'):
                messagebox.showerror("Invalid File", "Selected file is not an APK file.")
                return False

        # Validate traffic file if selected
        if traffic:
            if not os.path.exists(traffic):
                messagebox.showerror("File Not Found", f"Traffic log file not found:\n{traffic}")
                return False

        # Check output folder
        if not output:
            messagebox.showerror(
                "Output Required",
                "Please select an output folder for the reports."
            )
            return False

        if not os.path.isdir(output):
            messagebox.showerror("Invalid Folder", f"Output folder does not exist:\n{output}")
            return False

        return True

    def _run_analysis(self):
        """
        Start the analysis process.

        This method validates inputs and starts the analysis in a
        background thread to keep the GUI responsive.
        """
        # Prevent multiple simultaneous analyses
        if self.analysis_running:
            messagebox.showwarning("Analysis Running", "An analysis is already in progress.")
            return

        # Validate inputs
        if not self._validate_inputs():
            return

        # Clear previous results
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", tk.END)
        self.results_text.configure(state="disabled")

        # Show progress indicator
        self.progress.grid()
        self.progress.start(10)

        # Disable the run button during analysis
        self.run_button.configure(state="disabled")
        self.analysis_running = True

        # Update status
        self.status_var.set("Analysis in progress...")

        # Start analysis in a background thread
        analysis_thread = threading.Thread(
            target=self._analysis_worker,
            daemon=True
        )
        analysis_thread.start()

    def _display_banner(self):
        """Display the application banner."""
        self._queue_raw("=" * 70, "separator")
        self._queue_raw("        MOBILE APP PRIVACY LEAKAGE DETECTION REPORT", "header")
        self._queue_raw("=" * 70, "separator")
        self._queue_raw(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "dim")
        self._queue_raw("", "raw")

    def _display_static_analysis(self, static_results: Dict[str, Any]):
        """
        Display detailed static analysis results.

        Args:
            static_results: Results from analyze_apk()
        """
        self._queue_raw("-" * 70, "separator")
        self._queue_raw("                    STATIC ANALYSIS RESULTS", "header")
        self._queue_raw("-" * 70, "separator")
        self._queue_raw("", "raw")

        # ============================================================
        # Application Information
        # ============================================================
        app_info = static_results.get("app_info", {})
        if app_info and any(app_info.values()):
            self._queue_raw("APPLICATION INFORMATION", "subheader")
            self._queue_raw("-" * 40, "separator")

            if app_info.get("app_name"):
                self._queue_raw(f"  App Name:    {app_info.get('app_name', 'N/A')}", "data_value")
            if app_info.get("package_name"):
                self._queue_raw(f"  Package:     {app_info.get('package_name', 'N/A')}", "data_value")
            if app_info.get("version_name"):
                self._queue_raw(f"  Version:     {app_info.get('version_name', 'N/A')} (Code: {app_info.get('version_code', 'N/A')})", "data_value")
            if app_info.get("min_sdk"):
                self._queue_raw(f"  Min SDK:     {app_info.get('min_sdk', 'N/A')}", "data_value")
            if app_info.get("target_sdk"):
                self._queue_raw(f"  Target SDK:  {app_info.get('target_sdk', 'N/A')}", "data_value")
            self._queue_raw("", "raw")

        # ============================================================
        # Permissions Section
        # ============================================================
        permissions = static_results.get("permissions", [])
        self._queue_raw(f"PERMISSIONS ({len(permissions)} found)", "subheader")
        self._queue_raw("-" * 40, "separator")

        if permissions:
            # Group permissions by risk level
            high_perms = [p for p in permissions if p.get("risk_level") == "HIGH"]
            medium_perms = [p for p in permissions if p.get("risk_level") == "MEDIUM"]
            low_perms = [p for p in permissions if p.get("risk_level") == "LOW"]

            # Display HIGH risk permissions
            if high_perms:
                self._queue_raw("", "raw")
                self._queue_raw("  [HIGH RISK]", "perm_high")
                for perm in high_perms:
                    perm_name = perm.get("permission", "").replace("android.permission.", "")
                    self._queue_raw(f"    ● {perm_name}", "perm_high")
                    if perm.get("description"):
                        self._queue_raw(f"      └─ {perm.get('description')}", "dim")

            # Display MEDIUM risk permissions
            if medium_perms:
                self._queue_raw("", "raw")
                self._queue_raw("  [MEDIUM RISK]", "perm_medium")
                for perm in medium_perms:
                    perm_name = perm.get("permission", "").replace("android.permission.", "")
                    self._queue_raw(f"    ● {perm_name}", "perm_medium")
                    if perm.get("description"):
                        self._queue_raw(f"      └─ {perm.get('description')}", "dim")

            # Display LOW risk permissions
            if low_perms:
                self._queue_raw("", "raw")
                self._queue_raw("  [LOW RISK]", "perm_low")
                for perm in low_perms:
                    perm_name = perm.get("permission", "").replace("android.permission.", "")
                    self._queue_raw(f"    ● {perm_name}", "perm_low")
        else:
            self._queue_raw("  No permissions found", "dim")

        self._queue_raw("", "raw")

        # ============================================================
        # Sensitive APIs Section
        # ============================================================
        sensitive_apis = static_results.get("sensitive_apis", [])
        self._queue_raw(f"SENSITIVE APIs ({len(sensitive_apis)} found)", "subheader")
        self._queue_raw("-" * 40, "separator")

        if sensitive_apis:
            for api in sensitive_apis:
                risk = api.get("risk_level", "UNKNOWN")
                tag = "perm_high" if risk == "HIGH" else ("perm_medium" if risk == "MEDIUM" else "perm_low")
                self._queue_raw(f"  [{risk}] {api.get('api', 'Unknown')}", tag)
                if api.get("description"):
                    self._queue_raw(f"         └─ {api.get('description')}", "dim")
                if api.get("found_in"):
                    self._queue_raw(f"         └─ Found in: {api.get('found_in')}", "dim")
        else:
            self._queue_raw("  No sensitive APIs detected", "success")

        self._queue_raw("", "raw")

        # ============================================================
        # Network APIs Section
        # ============================================================
        network_apis = static_results.get("network_apis", [])
        self._queue_raw(f"NETWORK APIs ({len(network_apis)} found)", "subheader")
        self._queue_raw("-" * 40, "separator")

        if network_apis:
            for api in network_apis:
                self._queue_raw(f"  ● {api.get('api', 'Unknown')}", "info")
                if api.get("description"):
                    self._queue_raw(f"    └─ {api.get('description')}", "dim")
        else:
            self._queue_raw("  No network APIs detected", "dim")

        self._queue_raw("", "raw")

    def _display_dynamic_analysis(self, dynamic_results: Dict[str, Any]):
        """
        Display detailed dynamic analysis results.

        Args:
            dynamic_results: Results from analyze_traffic()
        """
        self._queue_raw("-" * 70, "separator")
        self._queue_raw("                   DYNAMIC ANALYSIS RESULTS", "header")
        self._queue_raw("-" * 70, "separator")
        self._queue_raw("", "raw")

        summary = dynamic_results.get("analysis_summary", {})

        # ============================================================
        # Traffic Summary
        # ============================================================
        self._queue_raw("TRAFFIC SUMMARY", "subheader")
        self._queue_raw("-" * 40, "separator")
        self._queue_raw(f"  Total HTTP Flows Analyzed:  {summary.get('total_flows', 0)}", "data_value")
        self._queue_raw(f"  Unique Hosts Contacted:     {summary.get('unique_hosts', 0)}", "data_value")
        self._queue_raw(f"  HTTP Methods Used:          {', '.join(dynamic_results.get('methods', ['N/A']))}", "data_value")
        self._queue_raw("", "raw")

        # ============================================================
        # Tracking Domains
        # ============================================================
        tracking = dynamic_results.get("tracking_domains", [])
        self._queue_raw(f"TRACKING/ANALYTICS DOMAINS ({len(tracking)} found)", "subheader")
        self._queue_raw("-" * 40, "separator")

        if tracking:
            for domain in tracking:
                self._queue_raw(f"  ⚠ {domain}", "warning")
        else:
            self._queue_raw("  No tracking domains detected", "success")

        self._queue_raw("", "raw")

        # ============================================================
        # Data Leaks Section
        # ============================================================
        leaks = dynamic_results.get("leaked_data_matches", [])
        high_leaks = sum(1 for l in leaks if l.get("risk_level") == "HIGH")
        med_leaks = sum(1 for l in leaks if l.get("risk_level") == "MEDIUM")

        self._queue_raw(f"DATA LEAKS DETECTED ({len(leaks)} found)", "subheader")
        self._queue_raw("-" * 40, "separator")

        if leaks:
            # Summary counts
            if high_leaks > 0:
                self._queue_raw(f"  HIGH risk leaks:   {high_leaks}", "perm_high")
            if med_leaks > 0:
                self._queue_raw(f"  MEDIUM risk leaks: {med_leaks}", "perm_medium")
            self._queue_raw("", "raw")

            # Group leaks by type for organized display
            leak_types = {}
            for leak in leaks:
                lt = leak.get("type", "unknown")
                if lt not in leak_types:
                    leak_types[lt] = []
                leak_types[lt].append(leak)

            for leak_type, type_leaks in leak_types.items():
                risk = type_leaks[0].get("risk_level", "UNKNOWN")
                tag = "perm_high" if risk == "HIGH" else ("perm_medium" if risk == "MEDIUM" else "perm_low")

                self._queue_raw(f"  [{risk}] {leak_type.upper().replace('_', ' ')}", tag)
                self._queue_raw(f"         Description: {type_leaks[0].get('description', 'N/A')}", "dim")

                # Show all occurrences
                for i, leak in enumerate(type_leaks):
                    value = leak.get("value", "")[:60]
                    location = leak.get("location", "")
                    url = leak.get("url", "")[:50] if leak.get("url") else ""

                    self._queue_raw(f"         Occurrence {i+1}:", "data_label")
                    self._queue_raw(f"           Value: {value}", "leak_value")
                    if location:
                        self._queue_raw(f"           Found in: {location}", "dim")
                    if url:
                        self._queue_raw(f"           URL: {url}...", "url")

                self._queue_raw("", "raw")
        else:
            self._queue_raw("  No data leaks detected in traffic", "success")

        self._queue_raw("", "raw")

        # ============================================================
        # URLs Contacted (Sample)
        # ============================================================
        urls = dynamic_results.get("urls", [])
        self._queue_raw(f"URLS CONTACTED ({len(urls)} total)", "subheader")
        self._queue_raw("-" * 40, "separator")

        if urls:
            for i, url in enumerate(urls[:15]):  # Show first 15
                # Truncate long URLs
                display_url = url[:80] + "..." if len(url) > 80 else url
                self._queue_raw(f"  {i+1}. {display_url}", "url")

            if len(urls) > 15:
                self._queue_raw(f"  ... and {len(urls) - 15} more URLs", "dim")
        else:
            self._queue_raw("  No URLs found in traffic", "dim")

        self._queue_raw("", "raw")

        # ============================================================
        # Hosts List
        # ============================================================
        hosts = dynamic_results.get("hosts", [])
        self._queue_raw(f"UNIQUE HOSTS ({len(hosts)} total)", "subheader")
        self._queue_raw("-" * 40, "separator")

        if hosts:
            for host in hosts[:20]:  # Show first 20
                self._queue_raw(f"  ● {host}", "data_value")
            if len(hosts) > 20:
                self._queue_raw(f"  ... and {len(hosts) - 20} more hosts", "dim")
        else:
            self._queue_raw("  No hosts found", "dim")

        self._queue_raw("", "raw")

    def _display_risk_assessment(self, risk_level: str, static_results: Dict, dynamic_results: Dict):
        """
        Display the overall risk assessment.

        Args:
            risk_level: The calculated risk level (HIGH/MEDIUM/LOW)
            static_results: Static analysis results
            dynamic_results: Dynamic analysis results
        """
        self._queue_raw("=" * 70, "separator")
        self._queue_raw("                    OVERALL RISK ASSESSMENT", "header")
        self._queue_raw("=" * 70, "separator")
        self._queue_raw("", "raw")

        # Display risk level with appropriate color
        risk_tag = {
            "HIGH": "risk_high",
            "MEDIUM": "risk_medium",
            "LOW": "risk_low"
        }.get(risk_level, "info")

        self._queue_raw(f"              ╔═══════════════════════════════╗", "separator")
        self._queue_raw(f"              ║    RISK LEVEL: {risk_level:^10}    ║", risk_tag)
        self._queue_raw(f"              ╚═══════════════════════════════╝", "separator")
        self._queue_raw("", "raw")

        # Risk explanation
        if risk_level == "HIGH":
            self._queue_raw("⚠️  WARNING: Critical privacy concerns detected!", "error")
            self._queue_raw("", "raw")
            self._queue_raw("The application shows evidence of collecting and potentially", "error")
            self._queue_raw("transmitting sensitive personal data without clear justification.", "error")
            self._queue_raw("", "raw")
            self._queue_raw("This includes one or more of:", "error")
            self._queue_raw("  • High-risk permissions (location, contacts, phone state)", "error")
            self._queue_raw("  • Sensitive API usage (device IDs, location data)", "error")
            self._queue_raw("  • Detected data leakage in network traffic", "error")
        elif risk_level == "MEDIUM":
            self._queue_raw("⚠️  CAUTION: Moderate privacy concerns detected.", "warning")
            self._queue_raw("", "raw")
            self._queue_raw("The application accesses some sensitive data and communicates", "warning")
            self._queue_raw("with tracking services. Review the findings above carefully.", "warning")
        else:
            self._queue_raw("✓  LOW RISK: Minimal privacy concerns detected.", "success")
            self._queue_raw("", "raw")
            self._queue_raw("The application appears to have limited access to sensitive data.", "success")
            self._queue_raw("Continue monitoring app behavior for any changes.", "success")

        self._queue_raw("", "raw")

        # ============================================================
        # Risk Factors Summary
        # ============================================================
        self._queue_raw("RISK FACTORS", "subheader")
        self._queue_raw("-" * 40, "separator")

        factors = []

        if static_results:
            high_perms = sum(1 for p in static_results.get("permissions", []) if p.get("risk_level") == "HIGH")
            if high_perms > 0:
                factors.append(f"• {high_perms} high-risk permissions requested")

            sensitive_apis = len(static_results.get("sensitive_apis", []))
            if sensitive_apis > 0:
                factors.append(f"• {sensitive_apis} sensitive APIs detected in code")

            network_apis = len(static_results.get("network_apis", []))
            if network_apis > 0 and sensitive_apis > 0:
                factors.append(f"• Network capability combined with sensitive data access")

        if dynamic_results:
            leaks = len(dynamic_results.get("leaked_data_matches", []))
            if leaks > 0:
                factors.append(f"• {leaks} potential data leaks detected in traffic")

            tracking = len(dynamic_results.get("tracking_domains", []))
            if tracking > 0:
                factors.append(f"• {tracking} tracking/analytics domains contacted")

        if factors:
            for factor in factors:
                tag = "error" if "high-risk" in factor.lower() or "leak" in factor.lower() else "warning"
                self._queue_raw(f"  {factor}", tag)
        else:
            self._queue_raw("  No significant risk factors identified", "success")

        self._queue_raw("", "raw")

    def _display_recommendations(self, risk_level: str, static_results: Dict, dynamic_results: Dict):
        """
        Display security recommendations based on findings.

        Args:
            risk_level: The calculated risk level
            static_results: Static analysis results
            dynamic_results: Dynamic analysis results
        """
        self._queue_raw("-" * 70, "separator")
        self._queue_raw("                       RECOMMENDATIONS", "header")
        self._queue_raw("-" * 70, "separator")
        self._queue_raw("", "raw")

        recommendations = []
        rec_num = 1

        if risk_level == "HIGH":
            recommendations.append("CRITICAL: Review the application's data collection practices immediately.")

        if static_results:
            high_perms = [p for p in static_results.get("permissions", []) if p.get("risk_level") == "HIGH"]
            if high_perms:
                recommendations.append(
                    f"Review the necessity of {len(high_perms)} high-risk permissions. "
                    "Consider if all permissions are essential for app functionality."
                )

            location_perms = [p for p in static_results.get("permissions", [])
                            if "LOCATION" in p.get("permission", "")]
            if location_perms:
                recommendations.append(
                    "Location access detected. Verify that location data is only collected "
                    "when necessary and users are properly informed."
                )

            if static_results.get("sensitive_apis") and static_results.get("network_apis"):
                recommendations.append(
                    "The app has both sensitive data access and network capabilities. "
                    "Audit data flows to ensure sensitive data is not transmitted unnecessarily."
                )

        if dynamic_results:
            leaks = dynamic_results.get("leaked_data_matches", [])
            if leaks:
                leak_types = set(l.get("type", "") for l in leaks)
                recommendations.append(
                    f"Data leaks detected ({', '.join(leak_types)}). "
                    "Implement data minimization and ensure only necessary data is transmitted."
                )

            tracking = dynamic_results.get("tracking_domains", [])
            if tracking:
                recommendations.append(
                    f"{len(tracking)} tracking/analytics services detected. "
                    "Review third-party SDKs and ensure compliance with privacy regulations."
                )

            urls = dynamic_results.get("urls", [])
            http_urls = [u for u in urls if u.startswith("http://")]
            if http_urls:
                recommendations.append(
                    f"{len(http_urls)} unencrypted HTTP connections detected. "
                    "Migrate all network traffic to HTTPS for secure transmission."
                )

        # Always add general recommendations
        recommendations.append(
            "Consider implementing a privacy policy that clearly explains data collection practices."
        )
        recommendations.append(
            "Regularly audit third-party libraries and SDKs for privacy compliance."
        )

        for rec in recommendations:
            tag = "error" if "CRITICAL" in rec else ("warning" if any(w in rec.lower() for w in ["review", "detected", "audit"]) else "info")
            self._queue_raw(f"  {rec_num}. {rec}", tag)
            self._queue_raw("", "raw")
            rec_num += 1

    def _analysis_worker(self):
        """
        Background worker thread for running the analysis.

        This runs the static and dynamic analysis without blocking the GUI.
        Results are communicated back via the message queue with full details.
        """
        apk_path = self.apk_path.get() or None
        traffic_path = self.traffic_path.get() or None
        output_folder = self.output_folder.get()

        # Generate output filename prefix based on timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_prefix = os.path.join(output_folder, f"privacy_report_{timestamp}")

        results = {
            "static_analysis": None,
            "dynamic_analysis": None,
            "reports": None,
            "success": False
        }

        try:
            # ==============================================================
            # Display banner
            # ==============================================================
            self._display_banner()

            # ==============================================================
            # STATIC ANALYSIS (if APK provided)
            # ==============================================================
            if apk_path:
                self._queue_message("Starting static analysis...", "info")
                self._queue_message(f"APK File: {os.path.basename(apk_path)}", "info")
                self._queue_raw("", "raw")

                try:
                    static_results = analyze_apk(apk_path)
                    results["static_analysis"] = static_results
                    self._queue_message("Static analysis completed!", "success")
                    self._queue_raw("", "raw")

                    # Display detailed static analysis
                    self._display_static_analysis(static_results)

                except Exception as e:
                    self._queue_message(f"Static analysis failed: {str(e)}", "error")
                    import traceback
                    self._queue_raw(traceback.format_exc(), "dim")

            # ==============================================================
            # DYNAMIC ANALYSIS (if traffic log provided)
            # ==============================================================
            if traffic_path:
                self._queue_message("Starting dynamic analysis...", "info")
                self._queue_message(f"Traffic Log: {os.path.basename(traffic_path)}", "info")
                self._queue_raw("", "raw")

                try:
                    dynamic_results = analyze_traffic(traffic_path)
                    results["dynamic_analysis"] = dynamic_results
                    self._queue_message("Dynamic analysis completed!", "success")
                    self._queue_raw("", "raw")

                    # Display detailed dynamic analysis
                    self._display_dynamic_analysis(dynamic_results)

                except Exception as e:
                    self._queue_message(f"Dynamic analysis failed: {str(e)}", "error")
                    import traceback
                    self._queue_raw(traceback.format_exc(), "dim")

            # ==============================================================
            # GENERATE REPORTS AND DISPLAY RISK ASSESSMENT
            # ==============================================================
            if results["static_analysis"] or results["dynamic_analysis"]:
                self._queue_message("Generating reports...", "info")

                try:
                    report_info = generate_report(
                        results["static_analysis"],
                        results["dynamic_analysis"],
                        output_prefix
                    )
                    results["reports"] = report_info
                    results["success"] = True

                    risk_level = report_info.get("risk_level", "UNKNOWN")

                    # Display risk assessment
                    self._display_risk_assessment(
                        risk_level,
                        results["static_analysis"],
                        results["dynamic_analysis"]
                    )

                    # Display recommendations
                    self._display_recommendations(
                        risk_level,
                        results["static_analysis"],
                        results["dynamic_analysis"]
                    )

                    # Report file locations
                    self._queue_raw("-" * 70, "separator")
                    self._queue_raw("                        REPORTS SAVED", "header")
                    self._queue_raw("-" * 70, "separator")
                    self._queue_raw("", "raw")
                    self._queue_raw(f"  JSON Report: {report_info.get('json_report', 'N/A')}", "success")
                    self._queue_raw(f"  Text Report: {report_info.get('text_report', 'N/A')}", "success")
                    self._queue_raw("", "raw")

                except Exception as e:
                    self._queue_message(f"Report generation failed: {str(e)}", "error")
            else:
                self._queue_message("No analysis results to report.", "warning")

            # ==============================================================
            # FINAL STATUS
            # ==============================================================
            self._queue_raw("=" * 70, "separator")
            if results["success"]:
                self._queue_raw("              ✓ ANALYSIS COMPLETED SUCCESSFULLY", "success")
            else:
                self._queue_raw("              ⚠ ANALYSIS COMPLETED WITH ERRORS", "warning")
            self._queue_raw("=" * 70, "separator")

        except Exception as e:
            self._queue_message(f"Unexpected error: {str(e)}", "error")
            import traceback
            self._queue_raw(traceback.format_exc(), "dim")

        finally:
            # Signal completion to main thread
            self.root.after(0, self._analysis_complete, results)

    def _analysis_complete(self, results: Dict[str, Any]):
        """
        Called when analysis is complete.

        Resets the UI state and shows completion message.

        Args:
            results: The analysis results dictionary
        """
        # Stop and hide progress bar
        self.progress.stop()
        self.progress.grid_remove()

        # Re-enable the run button
        self.run_button.configure(state="normal")
        self.analysis_running = False

        # Update status bar
        if results.get("success"):
            risk_level = results.get("reports", {}).get("risk_level", "UNKNOWN")
            self.status_var.set(f"Analysis complete. Risk Level: {risk_level}")

            # Show success message
            messagebox.showinfo(
                "Analysis Complete",
                f"Privacy analysis completed successfully!\n\n"
                f"Risk Level: {risk_level}\n\n"
                f"Reports saved to:\n{self.output_folder.get()}"
            )
        else:
            self.status_var.set("Analysis completed with errors. Check results for details.")


def main():
    """
    Main entry point for the GUI application.
    """
    # Create the main window
    root = tk.Tk()

    # Set app icon (if available) - Mac specific
    try:
        # On Mac, we can set the app to appear in dock properly
        root.createcommand('tk::mac::ReopenApplication', lambda: root.lift())
    except:
        pass

    # Apply a modern theme if available
    try:
        # Use 'aqua' theme on Mac for native look
        style = ttk.Style()
        if 'aqua' in style.theme_names():
            style.theme_use('aqua')
        elif 'clam' in style.theme_names():
            style.theme_use('clam')
    except:
        pass

    # Create and run the application
    app = PrivacyDetectorGUI(root)

    # Center the window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"+{x}+{y}")

    # Start the event loop
    root.mainloop()


if __name__ == "__main__":
    main()
