"""
0206 - Generic Self-Contained Report Template Definitions
Phase 21: Self-contained report styling, color palettes, and default layout.
Contains NO copyrighted or proprietary material.
"""
from typing import Dict, Any

# Standard 0206 Color Palette
COLOR_PALETTE = {
    "PRIMARY_DARK": "#1A202C",      # Dark Slate
    "SECONDARY_DARK": "#2D3748",    # Medium Slate
    "ACCENT_CYAN": "#00B4D8",       # Cyan highlight
    "ACCENT_RED": "#E63946",        # Malicious indicator red
    "ACCENT_AMBER": "#F77F00",      # Suspicious orange
    "ACCENT_GREEN": "#2A9D8F",      # Clean / Informational green
    "BORDER_GREY": "#E2E8F0",       # Table border light grey
    "BG_LIGHT": "#F8FAFC",          # Table zebra light background
}

GENERIC_REPORT_SECTIONS = [
    # PART I - Basic Analysis
    "Sample Identification",
    "Reputation Assessment",
    "Basic Static Analysis",
    "Basic Behavioral Analysis",
    "Preliminary Findings",
    "Initial Triage Assessment",
    # PART II - Advanced Analysis
    "Advanced Static Analysis",
    "Assembly & Code Analysis",
    "API & Control Flow Analysis",
    "Advanced Dynamic & Process Analysis",
    "Memory Analysis",
    "Network & C2 Analysis",
    "Persistence Analysis",
    "Anti-Analysis & Defense Evasion",
    "Unpacking & Obfuscation",
    "Cross-Stage Correlation & Final Synthesis",
    # Appended sections
    "Indicators of Compromise (IOCs)",
    "MITRE ATT&CK Matrix",
    "Analysis Coverage Matrix",
    "Limitations & Analytical Priorities",
    "Evidence Appendix",
    "Analysis Manifest & Provenance",
]
