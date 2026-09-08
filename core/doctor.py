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

    # Optional Tier 2 Table
    opt_table = Table(title="⚙️ OPTIONAL Tier 2 Open-Source Analyzers (Enhancement Only)", show_header=True, header_style="bold yellow")
    opt_table.add_column("Analyzer", style="bold white", width=18)
    opt_table.add_column("Status", width=16)
    opt_table.add_column("Details / Binary Path", style="dim")

    tier2_tools = ["YARA", "capa", "Ghidra", "radare2", "pe-sieve", "FLOSS"]
    tier2_available = 0

    for tool in tier2_tools:
        info = caps.get(tool, {"status": "NOT_INSTALLED"})
        status = info.get("status", "NOT_INSTALLED")
        if status == "AVAILABLE":
            tier2_available += 1
            status_str = "[bold green]AVAILABLE  ✓[/bold green]"
            details = info.get("path") or info.get("version") or "Installed"
        else:
            status_str = "[yellow]NOT_INSTALLED[/yellow]"
            details = "Optional enhancement"
        opt_table.add_row(tool, status_str, details)

    console.print(opt_table)
    console.print("")

    # Proprietary Tier 3 Table
    prop_table = Table(title="🔒 PROPRIETARY Tier 3 Tools (External / User-Provided)", show_header=True, header_style="bold magenta")
    prop_table.add_column("Tool", style="bold white", width=18)
    prop_table.add_column("Status", width=16)
    prop_table.add_column("Details", style="dim")

    tier3_tools = ["IDA Pro", "x64dbg", "WinDbg"]
    tier3_available = 0

    for tool in tier3_tools:
        info = caps.get(tool, {"status": "NOT_INSTALLED"})
        status = info.get("status", "NOT_INSTALLED")
        if status == "AVAILABLE":
            tier3_available += 1
            status_str = "[bold green]AVAILABLE  ✓[/bold green]"
            details = info.get("path", "Detected")
        elif status == "NOT_AVAILABLE_ON_PLATFORM":
            status_str = "[dim]N/A ON OS[/dim]"
            details = f"Not supported on {platform.system()}"
        else:
            status_str = "[dim yellow]NOT_INSTALLED[/dim yellow]"
            details = "Optional external tool"
        prop_table.add_row(tool, status_str, details)

    console.print(prop_table)
    console.print("")

    # Summary Panel
    status_label = "[bold green]CORE READY[/bold green]" if all_core_ok else "[bold red]CORE INCOMPLETE (Install missing core packages)[/bold red]"
    border_col = "green" if all_core_ok else "red"

    summary = (
        f"[bold white]STATUS:[/bold white] {status_label}\n"
        f"  • [cyan]OPTIONAL ANALYZERS:[/cyan]    {tier2_available}/{len(tier2_tools)} available\n"
        f"  • [cyan]PROPRIETARY ANALYZERS:[/cyan] {tier3_available}/{len(tier3_tools)} available\n\n"
        f"[dim]Environment Specs:[/dim]\n"
        f"  • Python: {sys.version.split()[0]} | Platform: {platform.system()} ({platform.machine()})\n"
        f"  • Privacy Mode: strict (default) | Default AI: offline (deterministic)\n"
        f"  • Evidence Model: Canonical 3-Tier (EvidenceRecord -> Finding -> Assessment)\n"
        f"  • Template Mode: Built-in Generic (User-provided DOCX supported via --template)"
    )

    console.print(Panel(summary, title="🏥 Doctor Diagnosis Summary", border_style=border_col))
    return all_core_ok
