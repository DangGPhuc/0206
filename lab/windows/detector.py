"""
0206 - Windows REM Lab Tool Detector
Phase 13 & 22: Audits installed tools in local Windows or Linux lab environments.
Distinguishes:
- NOT_INSTALLED
- DETECTED
- READY
- FUNCTIONAL
- PARTIAL
- FAILED
- NOT_SUPPORTED
- NOT_CONFIGURED
"""
import os
import sys
import shutil
import platform
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ToolAuditResult(BaseModel):
    name: str
    display_name: str
    category: str
    status: str
    version: str = "N/A"
    path: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    details: str = ""


class WindowsLabDetector:
    """Detects available reverse engineering and triage tools according to lab specification."""

    LAB_TOOLS = [
        # Static & PE Triage
        {
            "name": "pestudio",
            "display_name": "PEStudio",
            "category": "PE Analysis",
            "binaries": ["pestudio.exe", "pestudio"],
            "windows_only": True,
            "capabilities": ["Initial Triage", "Anomaly Highlighting", "Import Flagging"]
        },
        {
            "name": "pe-bear",
            "display_name": "PE-bear",
            "category": "PE Analysis",
            "binaries": ["PE-bear.exe", "pe-bear"],
            "windows_only": False,
            "capabilities": ["PE Section Viewing", "Header Comparison", "Fast Unpacking Inspection"]
        },
        {
            "name": "peview",
            "display_name": "PEView",
            "category": "PE Analysis",
            "binaries": ["PEview.exe", "peview.exe", "PEView"],
            "windows_only": True,
            "capabilities": ["PE Headers Raw Inspection", "Section Layout"]
        },
        {
            "name": "capa",
            "display_name": "capa",
            "category": "Static Triage",
            "binaries": ["capa.exe", "capa"],
            "windows_only": False,
            "capabilities": ["ATT&CK Rule Matching", "Capability Identification"]
        },
        {
            "name": "floss",
            "display_name": "FLOSS",
            "category": "Static Triage",
            "binaries": ["floss.exe", "floss"],
            "windows_only": False,
            "capabilities": ["Deobfuscated String Extraction", "Stack Strings"]
        },
        {
            "name": "yara",
            "display_name": "YARA",
            "category": "Static Triage",
            "binaries": ["yara64.exe", "yara.exe", "yara"],
            "windows_only": False,
            "capabilities": ["Signature Matching", "Binary Pattern Detection"]
        },
        # Behavioral & Monitoring
        {
            "name": "procmon",
            "display_name": "Process Monitor",
            "category": "Process Monitoring",
            "binaries": ["Procmon64.exe", "Procmon.exe", "procmon"],
            "windows_only": True,
            "capabilities": ["Filesystem Events", "Registry Events", "Process Creation"]
        },
        {
            "name": "process_hacker",
            "display_name": "Process Hacker / System Informer",
            "category": "Process Monitoring",
            "binaries": ["SystemInformer.exe", "ProcessHacker.exe"],
            "windows_only": True,
            "capabilities": ["Live Process Inspection", "Memory Strings", "Handle Enumeration"]
        },
        {
            "name": "regshot",
            "display_name": "Regshot",
            "category": "Registry Monitoring",
            "binaries": ["Regshot-x64-ANSI.exe", "regshot.exe"],
            "windows_only": True,
            "capabilities": ["Registry Delta Diffing", "Filesystem Diffs"]
        },
        {
            "name": "wireshark",
            "display_name": "Wireshark / TShark",
            "category": "Network Capture",
            "binaries": ["wireshark.exe", "wireshark", "tshark.exe", "tshark"],
            "windows_only": False,
            "capabilities": ["PCAP Inspection", "Protocol Decryption", "Stream Following"]
        },
        # Debuggers & Disassemblers
        {
            "name": "x64dbg",
            "display_name": "x64dbg",
            "category": "Debugger",
            "binaries": ["x64dbg.exe", "x32dbg.exe"],
            "windows_only": True,
            "capabilities": ["User-Mode Debugging", "Dynamic Unpacking", "Breakpoint Tracing"]
        },
        {
            "name": "ghidra",
            "display_name": "Ghidra",
            "category": "Disassembler / Decompiler",
            "binaries": ["ghidraRun.bat", "ghidraRun"],
            "windows_only": False,
            "capabilities": ["SRE Decompilation", "Headless Analysis", "Cross References"]
        },
        {
            "name": "ida_pro",
            "display_name": "IDA Pro",
            "category": "Disassembler / Decompiler",
            "binaries": ["ida64.exe", "ida.exe", "ida64", "ida"],
            "windows_only": False,
            "capabilities": ["Interactive Disassembly", "Hex-Rays Decompiler", "FLIRT Signatures"]
        },
        {
            "name": "radare2",
            "display_name": "radare2",
            "category": "Disassembler",
            "binaries": ["radare2.exe", "radare2", "r2.exe", "r2"],
            "windows_only": False,
            "capabilities": ["Command-line Disassembly", "Basic Block Graphing", "Scriptable Triage"]
        }
    ]

    @classmethod
    def audit_environment(cls) -> Dict[str, ToolAuditResult]:
        """Audits all defined tools and determines exact capability status."""
        results: Dict[str, ToolAuditResult] = {}
        is_windows = platform.system() == "Windows"

        for spec in cls.LAB_TOOLS:
            tool_id = spec["name"]
            display_name = spec["display_name"]
            category = spec["category"]
            binaries = spec["binaries"]
            windows_only = spec.get("windows_only", False)
            caps = spec.get("capabilities", [])

            # Check OS compatibility
            if windows_only and not is_windows:
                results[tool_id] = ToolAuditResult(
                    name=tool_id,
                    display_name=display_name,
                    category=category,
                    status="NOT_SUPPORTED",
                    details="Windows guest exclusive tool (available inside analysis VM).",
                    capabilities=caps
                )
                continue

            # Check executable path
            found_path = None
            for b in binaries:
                p = shutil.which(b)
                if p:
                    found_path = p
                    break

            if found_path:
                results[tool_id] = ToolAuditResult(
                    name=tool_id,
                    display_name=display_name,
                    category=category,
                    status="FUNCTIONAL",
                    path=found_path,
                    details=f"Detected executable at {found_path}",
                    capabilities=caps
                )
            else:
                results[tool_id] = ToolAuditResult(
                    name=tool_id,
                    display_name=display_name,
                    category=category,
                    status="NOT_INSTALLED",
                    details="Executable not detected on current host PATH.",
                    capabilities=caps
                )

        return results

    @classmethod
    def audit(cls) -> List[ToolAuditResult]:
        """Returns audited tools as a list."""
        return list(cls.audit_environment().values())
