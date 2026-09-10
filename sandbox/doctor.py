"""
0206 - Sandbox Doctor Diagnostic Module
Performs read-only validation of hypervisor, VM, baseline snapshot,
network isolation, and in-guest telemetry tools.
CRITICAL SAFETY GUARANTEE: NEVER executes untrusted code or samples.
"""
import shutil
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from sandbox.schema import SandboxGuestConfig, ActionStatus, SandboxNetworkState
from sandbox.backends.virtualbox import VirtualBoxSandboxBackend


def run_sandbox_doctor(
    console: Console,
    backend_name: str = "virtualbox",
    config: Optional[SandboxGuestConfig] = None
) -> bool:
    """
    Runs comprehensive read-only sandbox diagnostic check.
    Verifies:
      1. Hypervisor CLI (VBoxManage) exists
      2. Configured target VM exists
      3. Clean baseline snapshot exists
      4. Safe network isolation (host-only / internal; no NAT/Bridged)
      5. Guest control capability
      6. Telemetry capture tools configured
    Returns True if sandbox environment is fully eligible for live detonation.
    """
    cfg = config or SandboxGuestConfig()
    backend_type = (backend_name or cfg.backend or "virtualbox").lower()

    title_text = f"🧪 Sandbox Diagnostic Check: {backend_type.upper()}"
    console.print(Panel(f"Target VM: [cyan]{cfg.vm_name}[/cyan] | Snapshot: [cyan]{cfg.snapshot_name}[/cyan] | Network Mode: [cyan]{cfg.network_mode}[/cyan]", title=title_text, border_style="cyan"))

    if backend_type != "virtualbox":
        table = Table(title=f"Hypervisor Backend: {backend_type}", show_header=True, header_style="bold yellow")
        table.add_column("Component", style="bold white", width=24)
        table.add_column("Status", width=18)
        table.add_column("Details", style="dim")
        table.add_row("Backend Architecture", "[yellow]SCAFFOLD[/yellow]", f"Backend '{backend_type}' is currently scaffolded. Live detonation requires 'virtualbox'.")
        console.print(table)
        return False

    vbox = VirtualBoxSandboxBackend(config=cfg)

    table = Table(title="🔬 VirtualBox Live Detonation Readiness", show_header=True, header_style="bold cyan")
    table.add_column("Diagnostic Check", style="bold white", width=26)
    table.add_column("Status", width=18)
    table.add_column("Details", style="dim")

    all_passed = True

    # 1. VBoxManage CLI check
    if vbox.is_available():
        table.add_row("VBoxManage Binary", "[bold green]AVAILABLE  ✓[/bold green]", f"Found: {vbox.vbox_bin}")
    else:
        table.add_row("VBoxManage Binary", "[bold red]MISSING     ✗[/bold red]", "VBoxManage executable not found in PATH.")
        all_passed = False

    # 2. VM existence check
    vm_rec = vbox.verify_vm()
    if vm_rec.is_success():
        table.add_row("Target Virtual Machine", "[bold green]VERIFIED   ✓[/bold green]", f"VM '{cfg.vm_name}' registered and accessible.")
    else:
        table.add_row("Target Virtual Machine", "[bold red]FAILED      ✗[/bold red]", vm_rec.details)
        all_passed = False

    # 3. Snapshot existence check
    snap_rec = vbox.verify_baseline()
    if snap_rec.is_success():
        table.add_row("Baseline Snapshot", "[bold green]VERIFIED   ✓[/bold green]", f"Clean snapshot '{cfg.snapshot_name}' verified.")
    else:
        table.add_row("Baseline Snapshot", "[bold red]FAILED      ✗[/bold red]", snap_rec.details)
        all_passed = False

    # 4. Network isolation check (default-deny)
    net_rec = vbox.verify_network()
    if net_rec.is_success():
        net_style = "bold green"
        table.add_row("Network Safety Inspection", f"[{net_style}]VERIFIED   ✓[/{net_style}]", net_rec.details)
    else:
        net_style = "bold red"
        table.add_row("Network Safety Inspection", f"[{net_style}]INSECURE    ✗[/{net_style}]", net_rec.details)
        all_passed = False

    # 5. Guest Control & Credentials
    user = cfg.guest_username
    has_pwd = bool(cfg.get_guest_password())
    if has_pwd:
        table.add_row("Guest Credentials", "[bold green]CONFIGURED ✓[/bold green]", f"User: '{user}', Password resolved from env '${cfg.guest_password_env}'.")
    else:
        table.add_row("Guest Credentials", "[yellow]NOT_SET    ▲[/yellow]", f"Env var '${cfg.guest_password_env}' is empty. In-guest execution will fail without credentials.")
        all_passed = False

    # 6. Telemetry capability requirements
    telemetry_summary = []
    if cfg.enable_procmon:
        telemetry_summary.append("Procmon (CSV)")
    if cfg.enable_pcap:
        telemetry_summary.append("Wireshark/tshark (PCAP)")
    if cfg.enable_regshot:
        telemetry_summary.append("Regshot (Diff)")

    table.add_row("Telemetry Collectors", "[cyan]CONFIGURED ●[/cyan]", f"Active monitors: {', '.join(telemetry_summary)}.")

    console.print(table)
    console.print("")

    if all_passed:
        console.print("[bold green]✔ Sandbox environment is VERIFIED and ready for live detonation.[/bold green]")
        console.print("[dim]Run detonation with: 0206 analyze <sample.exe> --detonate --sandbox virtualbox[/dim]\n")
    else:
        console.print("[bold yellow]▲ Sandbox environment has unmet requirements. Live detonation will be BLOCKED fail-closed.[/bold yellow]\n")

    return all_passed
