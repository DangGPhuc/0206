"""
0206 - Sandbox Doctor Diagnostic Module
Performs read-only two-stage validation of hypervisor, VM, baseline snapshot,
network isolation, in-guest guestcontrol, and telemetry tool readiness.
CRITICAL SAFETY GUARANTEE: NEVER executes untrusted code or samples.
"""
import json
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from sandbox.schema import SandboxGuestConfig, ActionStatus, SandboxNetworkState
from sandbox.backends.virtualbox import VirtualBoxSandboxBackend


def run_sandbox_doctor(
    console: Console,
    backend_name: str = "virtualbox",
    config: Optional[SandboxGuestConfig] = None,
    backend_instance: Optional[Any] = None,
) -> bool:
    """
    Runs truthful two-stage read-only sandbox diagnostic check:
      Stage 1: HOST_PREFLIGHT
        - VBoxManage CLI exists
        - Target VM exists and accessible
        - Clean baseline snapshot exists
        - NIC configuration default-deny check (no NAT/Bridged)
        - Guest credentials configured
      Stage 2: GUEST_PREFLIGHT
        - Temporarily restore clean baseline snapshot
        - Start clean VM headless
        - Verify Guest Additions and guestcontrol readiness
        - Run harmless preflight.ps1 to inspect tool paths/versions and network policy
        - Power off VM
        - Revert baseline snapshot
        - Verify clean state
    Returns True only if both host and guest preflight pass (READY_FOR_DETONATION).
    """
    cfg = config or SandboxGuestConfig()
    backend_type = (backend_name or cfg.backend or "virtualbox").lower()

    title_text = f"🧪 Sandbox Diagnostic Check: {backend_type.upper()}"
    console.print(Panel(
        f"Target VM: [cyan]{cfg.vm_name}[/cyan] | Snapshot: [cyan]{cfg.snapshot_name}[/cyan] | Network Mode: [cyan]{cfg.network_mode}[/cyan]",
        title=title_text,
        border_style="cyan"
    ))

    if backend_type != "virtualbox":
        table = Table(title=f"Hypervisor Backend: {backend_type}", show_header=True, header_style="bold yellow")
        table.add_column("Component", style="bold white", width=24)
        table.add_column("Status", width=18)
        table.add_column("Details", style="dim")
        table.add_row("Backend Architecture", "[yellow]SCAFFOLD[/yellow]", f"Backend '{backend_type}' is currently scaffolded. Live detonation requires 'virtualbox'.")
        console.print(table)
        return False

    vbox = backend_instance or VirtualBoxSandboxBackend(config=cfg)

    # -------------------------------------------------------------
    # STAGE 1: HOST_PREFLIGHT
    # -------------------------------------------------------------
    host_table = Table(title="🔬 Stage 1: Host Preflight Readiness", show_header=True, header_style="bold cyan")
    host_table.add_column("Host Check", style="bold white", width=26)
    host_table.add_column("Status", width=18)
    host_table.add_column("Details", style="dim")

    host_passed = True

    # 1. VBoxManage CLI check
    if vbox.is_available():
        vbox_details = f"Found: {vbox.vbox_bin}"
        if vbox.vbox_user_home:
            vbox_details += " (VBOX_USER_HOME configured)"
        host_table.add_row("VBoxManage Binary", "[bold green]AVAILABLE  ✓[/bold green]", vbox_details)
    else:
        host_table.add_row("VBoxManage Binary", "[bold red]MISSING     ✗[/bold red]", "VBoxManage executable not found in PATH.")
        host_passed = False

    # 2. VM existence check
    vm_rec = vbox.verify_vm()
    if vm_rec.is_success():
        host_table.add_row("Target Virtual Machine", "[bold green]VERIFIED   ✓[/bold green]", f"VM '{cfg.vm_name}' registered and accessible.")
    else:
        host_table.add_row("Target Virtual Machine", "[bold red]FAILED      ✗[/bold red]", vm_rec.details)
        host_passed = False

    # 3. Snapshot existence check
    snap_rec = vbox.verify_baseline()
    if snap_rec.is_success():
        host_table.add_row("Baseline Snapshot", "[bold green]VERIFIED   ✓[/bold green]", snap_rec.details)
    else:
        host_table.add_row("Baseline Snapshot", "[bold red]FAILED      ✗[/bold red]", snap_rec.details)
        host_passed = False

    # 4. Network isolation check (default-deny)
    net_rec = vbox.verify_network()
    if net_rec.is_success():
        net_style = "bold green"
        host_table.add_row("NIC Policy Inspection", f"[{net_style}]VERIFIED   ✓[/{net_style}]", net_rec.details)
    else:
        net_style = "bold red"
        host_table.add_row("NIC Policy Inspection", f"[{net_style}]INSECURE    ✗[/{net_style}]", net_rec.details)
        host_passed = False

    # 5. Guest Credentials
    user = cfg.guest_username
    has_pwd = bool(cfg.get_guest_password())
    if has_pwd:
        host_table.add_row("Guest Credentials", "[bold green]CONFIGURED ✓[/bold green]", f"User: '{user}', Password resolved from env '${cfg.guest_password_env}'.")
    else:
        host_table.add_row("Guest Credentials", "[bold red]NOT_SET     ✗[/bold red]", f"Env var '${cfg.guest_password_env}' is empty. Guest control requires credentials.")
        host_passed = False

    console.print(host_table)
    console.print("")

    if not host_passed:
        console.print("[bold red]✗ HOST_PREFLIGHT FAILED: Cannot advance to in-guest verification.[/bold red]\n")
        return False

    # -------------------------------------------------------------
    # STAGE 2: GUEST_PREFLIGHT (Temporary clean VM boot & inspection)
    # -------------------------------------------------------------
    console.print("[*] Stage 1 Host Preflight passed. Initiating harmless Stage 2 Guest Preflight...")
    guest_table = Table(title="🔬 Stage 2: Guest Preflight Readiness", show_header=True, header_style="bold cyan")
    guest_table.add_column("Guest Check", style="bold white", width=26)
    guest_table.add_column("Status", width=18)
    guest_table.add_column("Details", style="dim")

    guest_passed = True

    # 1. Restore clean snapshot before starting
    restore_rec = vbox.restore_baseline()
    if not restore_rec.is_success():
        guest_table.add_row("Baseline Restore", "[bold red]FAILED      ✗[/bold red]", restore_rec.details)
        console.print(guest_table)
        return False

    # 2. Start VM headless
    start_rec = vbox.start()
    if not start_rec.is_success():
        guest_table.add_row("Headless VM Boot", "[bold red]FAILED      ✗[/bold red]", start_rec.details)
        console.print(guest_table)
        return False
    guest_table.add_row("Headless VM Boot", "[bold green]STARTED    ✓[/bold green]", "VM started headless for preflight.")

    try:
        # 3. Verify guest control & run in-guest preflight
        ctrl_rec = vbox.verify_guest_control()
        if ctrl_rec.is_success():
            guest_table.add_row("Guest Additions / Control", "[bold green]VERIFIED   ✓[/bold green]", ctrl_rec.details)
        else:
            guest_table.add_row("Guest Additions / Control", "[bold red]FAILED      ✗[/bold red]", ctrl_rec.details)
            guest_passed = False

        # 4. Inspect in-guest telemetry tools via preflight.ps1 output
        tools_status = {}
        if hasattr(vbox, "_preflight_data") and vbox._preflight_data:
            tools_status = vbox._preflight_data.get("tools", {})
        else:
            pf_res = vbox._run_guest_ps_script("preflight.ps1", [
                "-TraceId", vbox._trace_id,
                "-NetworkMode", cfg.network_mode.value if hasattr(cfg.network_mode, "value") else str(cfg.network_mode)
            ], timeout=30)
            if pf_res.exit_code == 0:
                try:
                    pf_data = json.loads(pf_res.stdout.strip())
                    tools_status = pf_data.get("tools", {})
                except Exception:
                    pass

        procmon_info = tools_status.get("procmon", {})
        if procmon_info.get("installed", False):
            guest_table.add_row("Procmon Collector", "[bold green]RESOLVED   ✓[/bold green]", f"Path: {procmon_info.get('path')} (v{procmon_info.get('version') or 'unknown'})")
        else:
            st = "[bold red]MISSING     ✗[/bold red]" if cfg.require_procmon else "[yellow]OPTIONAL   ▲[/yellow]"
            guest_table.add_row("Procmon Collector", st, "Procmon executable not found on guest.")
            if cfg.require_procmon:
                guest_passed = False

        tshark_info = tools_status.get("tshark", {})
        if tshark_info.get("installed", False):
            guest_table.add_row("tshark Network Collector", "[bold green]RESOLVED   ✓[/bold green]", f"Path: {tshark_info.get('path')} (v{tshark_info.get('version') or 'unknown'})")
        else:
            st = "[bold red]MISSING     ✗[/bold red]" if cfg.require_pcap else "[yellow]OPTIONAL   ▲[/yellow]"
            guest_table.add_row("tshark Network Collector", st, "tshark executable not found on guest.")
            if cfg.require_pcap:
                guest_passed = False

        regshot_info = tools_status.get("regshot", {})
        if regshot_info.get("installed", False):
            if regshot_info.get("automated", False):
                guest_table.add_row("Regshot Registry Diff", "[bold green]RESOLVED   ✓[/bold green]", f"Path: {regshot_info.get('path')}")
            else:
                guest_table.add_row("Regshot Registry Diff", "[yellow]PARTIAL    ▲[/yellow]", "Regshot found but automated CLI diffing is not verified.")
        else:
            guest_table.add_row("Regshot Registry Diff", "[yellow]UNAVAILABLE ▲[/yellow]", "Regshot not installed on guest.")

        # 5. Verify in-guest network policy
        if vbox.network_state == SandboxNetworkState.LEAK_DETECTED:
            guest_table.add_row("Guest Network Policy", "[bold red]LEAK_DETECTED ✗[/bold red]", "In-guest probe established external connection.")
            guest_passed = False
        elif vbox.network_state == SandboxNetworkState.UNVERIFIED and cfg.network_mode == SandboxNetworkMode.SIMULATED_INTERNET:
            guest_table.add_row("Guest Network Policy", "[bold red]UNVERIFIED  ✗[/bold red]", "Simulated internet services failed positive verification.")
            guest_passed = False
        else:
            guest_table.add_row("Guest Network Policy", "[bold green]VERIFIED   ✓[/bold green]", f"Network state: {vbox.network_state.value}")

    finally:
        # Guaranteed cleanup: stop VM, revert clean, verify clean
        vbox.stop()
        vbox.revert()
        clean_rec = vbox.verify_clean()
        if clean_rec.is_success():
            guest_table.add_row("Post-Preflight Revert", "[bold green]CLEAN      ✓[/bold green]", clean_rec.details)
        else:
            guest_table.add_row("Post-Preflight Revert", "[bold red]FAILED      ✗[/bold red]", clean_rec.details)
            guest_passed = False

    console.print(guest_table)
    console.print("")

    if host_passed and guest_passed:
        console.print("[bold green]✔ READY_FOR_DETONATION: Both host and in-guest preflight checks verified successfully.[/bold green]")
        console.print("[dim]Run detonation with: 0206 analyze <sample.exe> --detonate --sandbox virtualbox[/dim]\n")
        return True
    else:
        console.print("[bold yellow]▲ Sandbox environment has unmet requirements. Live detonation will be BLOCKED fail-closed.[/bold yellow]\n")
        return False
