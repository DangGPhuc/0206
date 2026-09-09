"""
0206 - Doctor Diagnostics & Environment Health Check
Inspects core requirements, optional open-source analyzers, proprietary tools,
operating system, and active platform configurations.
Never reports missing optional tools as application failures.
"""
import sys
import platform
from typing import Dict, Any
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from integrations.registry import CapabilityRegistry
from lab.windows.detector import WindowsLabDetector
from config import ENGINE_NAME, ENGINE_VERSION


def run_doctor(console: Console) -> bool:
    """
    Executes the comprehensive environment & capabilities diagnostic check.
    Returns True if Core (Tier 1) is ready, False otherwise.
    """
    caps = CapabilityRegistry.get_capabilities()

    # Create Core Requirements Table
    core_table = Table(title="📦 CORE Tier 1 Packages (Mandatory for Triage)", show_header=True, header_style="bold cyan")
    core_table.add_column("Component", style="bold white", width=18)
    core_table.add_column("Status", width=16)
    core_table.add_column("Version", style="italic green")

    core_packages = ["pefile", "scapy", "capstone", "python-docx", "pydantic", "rich"]
    all_core_ok = True

    # Python itself
    core_table.add_row("Python", "[bold green]AVAILABLE  ✓[/bold green]", f"{sys.version.split()[0]} ({platform.python_implementation()})")

    for pkg in core_packages:
        info = caps.get(pkg, {"status": "MISSING", "version": "unknown"})
        status = info["status"]
        if status == "AVAILABLE":
            status_str = "[bold green]AVAILABLE  ✓[/bold green]"
            ver_str = info.get("version", "installed")
        else:
            status_str = "[bold red]MISSING     ✗[/bold red]"
            ver_str = "Not installed"
            all_core_ok = False
        core_table.add_row(pkg, status_str, ver_str)

    console.print(core_table)
    console.print("")

    def format_status(status_str: str) -> str:
        if status_str == "FUNCTIONAL":
            return "[bold green]FUNCTIONAL  ✓[/bold green]"
        elif status_str == "READY":
            return "[bold cyan]READY       ●[/bold cyan]"
        elif status_str == "DETECTED":
            return "[bold yellow]DETECTED    ▲[/bold yellow]"
        elif status_str == "PARTIAL":
            return "[yellow]PARTIAL     ~[/yellow]"
        elif status_str == "NOT_CONFIGURED":
            return "[dim yellow]NOT_CONFIGURED[/dim yellow]"
        elif status_str == "NOT_SUPPORTED":
            return "[dim]NOT_SUPPORTED[/dim]"
        elif status_str == "FAILED":
            return "[bold red]FAILED      ✗[/bold red]"
        return "[dim]NOT_INSTALLED[/dim]"

    # Optional Tier 2 Table
    opt_table = Table(title="⚙️ OPTIONAL Tier 2 Open-Source Analyzers (Enhancement Only)", show_header=True, header_style="bold yellow")
    opt_table.add_column("Analyzer", style="bold white", width=12)
    opt_table.add_column("Status", width=16)
    opt_table.add_column("Version", style="italic green", width=10)
    opt_table.add_column("Capabilities & Diagnostics", style="dim")

    tier2_tools = ["YARA", "capa", "Ghidra", "radare2", "pe-sieve", "FLOSS"]
    tier2_functional = 0

    for tool in tier2_tools:
        info = caps.get(tool, {"status": "NOT_INSTALLED", "version": "-", "details": "Optional"})
        status = info.get("status", "NOT_INSTALLED")
        if status in ("FUNCTIONAL", "READY", "DETECTED"):
            tier2_functional += 1
        status_disp = format_status(status)
        ver_disp = info.get("version", "-")
        diag_disp = info.get("details") or ", ".join(info.get("capabilities", []))
        opt_table.add_row(tool, status_disp, ver_disp, diag_disp)

    console.print(opt_table)
    console.print("")

    # Proprietary Tier 3 Table
    prop_table = Table(title="🔒 PROPRIETARY Tier 3 Tools (External / User-Provided)", show_header=True, header_style="bold magenta")
    prop_table.add_column("Tool", style="bold white", width=12)
    prop_table.add_column("Status", width=16)
    prop_table.add_column("Version", style="italic green", width=10)
    prop_table.add_column("Capabilities & Diagnostics", style="dim")

    tier3_tools = ["IDA Pro", "x64dbg", "WinDbg"]
    tier3_functional = 0

    for tool in tier3_tools:
        info = caps.get(tool, {"status": "NOT_INSTALLED", "version": "-", "details": "Optional external"})
        status = info.get("status", "NOT_INSTALLED")
        if status in ("FUNCTIONAL", "READY", "DETECTED"):
            tier3_functional += 1
        status_disp = format_status(status)
        ver_disp = info.get("version", "-")
        diag_disp = info.get("details") or ", ".join(info.get("capabilities", []))
        prop_table.add_row(tool, status_disp, ver_disp, diag_disp)

    console.print(prop_table)
    console.print("")

    # Lab Workstation Capabilities (Windows REM / SANS FOR610 Spec)
    lab_audit = WindowsLabDetector.audit()
    lab_table = Table(title="🔬 LAB WORKSTATION Capabilities (Windows REM / SANS FOR610 Spec)", show_header=True, header_style="bold blue")
    lab_table.add_column("Tool", style="bold white", width=16)
    lab_table.add_column("Category", style="cyan", width=20)
    lab_table.add_column("Status", width=16)
    lab_table.add_column("Version", style="italic green", width=10)
    lab_table.add_column("Diagnostics & Capabilities", style="dim")

    lab_detected_count = 0
    for audit_item in lab_audit:
        if audit_item.status in ("FUNCTIONAL", "READY", "DETECTED", "PARTIAL"):
            lab_detected_count += 1
        st_disp = format_status(audit_item.status)
        ver_disp = audit_item.version or "-"
        caps_summary = ", ".join(audit_item.capabilities[:2])
        diag_disp = f"{audit_item.details} ({caps_summary})" if caps_summary else audit_item.details
        lab_table.add_row(audit_item.display_name, audit_item.category, st_disp, ver_disp, diag_disp)

    console.print(lab_table)
    console.print("")

    # Summary Panel
    status_label = "[bold green]CORE READY[/bold green]" if all_core_ok else "[bold red]CORE INCOMPLETE (Install missing core packages)[/bold red]"
    border_col = "green" if all_core_ok else "red"

    summary = (
        f"[bold white]STATUS:[/bold white] {status_label}\n"
        f"  • [cyan]OPTIONAL ANALYZERS:[/cyan]    {tier2_functional}/{len(tier2_tools)} active/ready\n"
        f"  • [cyan]PROPRIETARY ANALYZERS:[/cyan] {tier3_functional}/{len(tier3_tools)} active/ready\n"
        f"  • [cyan]LAB WORKSTATION TOOLS:[/cyan] {lab_detected_count}/{len(lab_audit)} available in current environment\n\n"
        f"[dim]Environment Specs:[/dim]\n"
        f"  • Python: {sys.version.split()[0]} | Platform: {platform.system()} ({platform.machine()})\n"
        f"  • Privacy Mode: strict (default) | Default AI: offline (deterministic)\n"
        f"  • Evidence Model: Canonical 3-Tier (EvidenceRecord -> Finding -> Assessment)\n"
        f"  • Template Mode: Built-in Generic (User-provided DOCX supported via --template)"
    )

    console.print(Panel(summary, title="🏥 Doctor Diagnosis Summary", border_style=border_col))
    return all_core_ok

