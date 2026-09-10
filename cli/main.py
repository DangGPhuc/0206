#!/usr/bin/env python3
"""
0206: Independent, Local-First, Evidence-Driven Malware Analysis & Reporting Platform
CLI entry point supporting subcommands:
  0206 analyze <sample> [--pcap <pcap>] [--procmon <csv>] [--profile standard] [--offline] [--export-raw-evidence] [--json] [--quiet] [--no-color]
  0206 doctor
  0206 capabilities
  0206 validate-template <template.docx>
  0206 manifest [analysis_manifest.json]
  0206 verify-case [case_dir_or_manifest]
  0206 selftest
"""
import sys
import os
import json
import hashlib
import warnings
import argparse
from pathlib import Path
from typing import Optional

# Suppress benign third-party library warnings to maintain clean CLI presentation (P1.13)
warnings.filterwarnings("ignore", module="scapy.*")
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except Exception:
    pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.text import Text

from config import ENGINE_NAME, ENGINE_VERSION
from core.orchestrator import AnalysisOrchestrator, OrchestrationResult
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming
from core.doctor import run_doctor
from core.selftest import run_selftest
from reporting.validators import TemplateValidator
from sandbox.doctor import run_sandbox_doctor
from sandbox.schema import SandboxGuestConfig

console = Console()


def print_banner():
    """Renders the 0206 platform banner."""
    banner_text = Text()
    banner_text.append(f"⚡ {ENGINE_NAME} ⚡\n", style="bold cyan")
    banner_text.append(f"Independent, Local-First Malware Analysis & Reporting Platform (v{ENGINE_VERSION})\n", style="italic white")
    banner_text.append("Evidence Store • Finding Engine • Two-Stage Reporting • Provenance Audit", style="dim green")
    console.print(Panel(banner_text, border_style="cyan", expand=False))


def cmd_doctor():
    """Runs environment and tool capability health check."""
    run_doctor(console)


def cmd_capabilities():
    """Displays detailed capability matrix."""
    run_doctor(console)


def cmd_selftest():
    """Runs automated self-test suite."""
    success = run_selftest(console)
    if not success:
        sys.exit(1)


def cmd_validate_template(template_path: str):
    """Validates a user-provided DOCX report template."""
    p = Path(template_path)
    console.print(f"[*] Validating template structure: [cyan]{p.resolve()}[/cyan] ...")
    valid, warnings_list = TemplateValidator.validate_sans_style_template(p)
    if valid:
        console.print("[bold green]✔ Template is valid and compatible with SANS-style report adapter.[/bold green]")
        if warnings_list:
            for w in warnings_list:
                console.print(f"  [yellow]Warning:[/yellow] {w}")
    else:
        console.print("[bold red]✗ Template validation failed:[/bold red]")
        for w in warnings_list:
            console.print(f"  • {w}")
        sys.exit(1)


def cmd_manifest(manifest_path: Optional[str] = None):
    """Inspects and displays an AnalysisManifest file."""
    p = Path(manifest_path) if manifest_path else Path("output/analysis_manifest.json")
    if not p.exists():
        console.print(f"[bold red][!] Error:[/bold red] Manifest file not found at [cyan]{p.resolve()}[/cyan]")
        sys.exit(1)

    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        table = Table(title=f"📋 Analysis Manifest: {data.get('case_id', 'Unknown')}", show_header=True, header_style="bold cyan")
        table.add_column("Property", style="bold white", width=24)
        table.add_column("Value", style="cyan")

        table.add_row("Case ID", data.get("case_id", "N/A"))
        table.add_row("Engine Version", data.get("engine_version", "N/A"))
        table.add_row("Timestamp (UTC)", data.get("start_time_utc", "N/A"))
        table.add_row("Profile", data.get("profile", "N/A"))
        table.add_row("Privacy Mode", data.get("privacy_mode", "N/A"))
        table.add_row("AI Mode", data.get("ai_mode", "N/A"))
        table.add_row("Sample Filename", data.get("sample_filename", "N/A"))
        table.add_row("Sample SHA256", data.get("sample_hashes", {}).get("sha256", "N/A"))
        table.add_row("Enabled Analyzers", ", ".join(data.get("analyzers_enabled", [])) or "None")
        table.add_row("Warnings", str(len(data.get("warnings", []))))

        console.print(table)
        console.print("")

        lineage = data.get("output_lineage", {})
        if lineage:
            l_table = Table(title="📦 Output Artifact Lineage (SHA256)", show_header=True, header_style="bold green")
            l_table.add_column("Artifact Name", style="bold white", width=24)
            l_table.add_column("Size (Bytes)", style="dim", width=14)
            l_table.add_column("SHA256 Hash", style="green")

            for name, info in lineage.items():
                l_table.add_row(name, f"{info.get('size_bytes', 0):,}", info.get("sha256", "N/A"))
            console.print(l_table)

    except Exception as e:
        console.print(f"[bold red][!] Error parsing manifest:[/bold red] {e}")
        sys.exit(1)


def cmd_verify_case(case_path_str: Optional[str] = None):
    """Verifies cryptographic integrity of a case bundle and its manifest (P1.15)."""
    p = Path(case_path_str) if case_path_str else Path("output")
    if p.is_dir():
        manifest_file = p / "analysis_manifest.json"
        sha_file = p / "analysis_manifest.sha256"
        case_dir = p
    else:
        manifest_file = p
        sha_file = p.parent / "analysis_manifest.sha256"
        case_dir = p.parent

    if not manifest_file.exists():
        console.print(f"[bold red][!] Manifest not found:[/bold red] {manifest_file.resolve()}")
        sys.exit(1)

    table = Table(title=f"🔒 Case Cryptographic Verification: {case_dir.name}", show_header=True, header_style="bold cyan")
    table.add_column("Artifact Name", style="bold white", width=26)
    table.add_column("Expected SHA256", style="dim", width=20)
    table.add_column("Actual SHA256", style="dim", width=20)
    table.add_column("Integrity Status", width=18)

    all_valid = True

    # 1. Verify manifest companion sha256
    manifest_bytes = manifest_file.read_bytes()
    manifest_calc = hashlib.sha256(manifest_bytes).hexdigest()
    if sha_file.exists():
        expected_manifest_sha = sha_file.read_text(encoding="utf-8").strip().split()[0]
        if manifest_calc == expected_manifest_sha:
            table.add_row("analysis_manifest.json", f"{expected_manifest_sha[:16]}...", f"{manifest_calc[:16]}...", "[bold green]VALID ✓[/bold green]")
        else:
            all_valid = False
            table.add_row("analysis_manifest.json", f"{expected_manifest_sha[:16]}...", f"{manifest_calc[:16]}...", "[bold red]CORRUPTED ✗[/bold red]")
    else:
        table.add_row("analysis_manifest.json", "N/A (no .sha256)", f"{manifest_calc[:16]}...", "[yellow]UNVERIFIED[/yellow]")

    # 2. Verify lineage artifacts
    try:
        data = json.loads(manifest_bytes.decode("utf-8"))
        lineage = data.get("output_lineage", {})
        for name, info in lineage.items():
            expected = info.get("sha256", "N/A")
            art_file = case_dir / info.get("filename", name)
            if not art_file.exists():
                art_file = case_dir / name
            if not art_file.exists():
                all_valid = False
                table.add_row(name, f"{expected[:16]}...", "MISSING", "[bold red]MISSING ✗[/bold red]")
                continue

            actual = hash_file_streaming(art_file).get("sha256", "")
            if actual == expected:
                table.add_row(name, f"{expected[:16]}...", f"{actual[:16]}...", "[bold green]VALID ✓[/bold green]")
            else:
                all_valid = False
                table.add_row(name, f"{expected[:16]}...", f"{actual[:16]}...", "[bold red]MISMATCH ✗[/bold red]")
    except Exception as e:
        console.print(f"[bold red][!] Error inspecting manifest lineage:[/bold red] {e}")
        sys.exit(1)

    console.print(table)
    console.print("")
    if all_valid:
        console.print(Panel("[bold green]✔ All case artifacts cryptographically verified against audit manifest![/bold green]", border_style="green"))
    else:
        console.print(Panel("[bold red]✗ One or more case artifacts failed cryptographic verification.[/bold red]", border_style="red"))
        sys.exit(1)


def cmd_validate_case(case_path_str: Optional[str]):
    """Runs comprehensive semantic and evidence-consistency validation on a case directory."""
    if not case_path_str:
        console.print("[bold red]Error: Please specify the case directory path to validate.[/bold red]")
        sys.exit(1)

    p = Path(case_path_str).resolve()
    if p.is_file():
        p = p.parent

    console.print(Panel(
        f"[bold cyan]🔍 0206 Case Semantic & Integrity Validator[/bold cyan]\n"
        f"[dim]Target Case Directory: {p}[/dim]",
        border_style="cyan"
    ))

    from core.semantic_validator import CaseSemanticValidator
    validator = CaseSemanticValidator()
    result = validator.validate_case(p)

    table = Table(title="Semantic Validation Rules", show_header=True, header_style="bold cyan")
    table.add_column("Rule / Check", style="bold white", width=32)
    table.add_column("Scope / Message", style="dim", width=46)
    table.add_column("Status", width=12)

    for issue in result.issues:
        color = "green" if issue.severity == "PASS" else ("yellow" if issue.severity == "WARNING" else "red")
        status_text = f"[{color}]{issue.severity}[/{color}]"
        table.add_row(issue.rule, issue.message, status_text)

    console.print(table)
    console.print("")

    if result.status == "PASS":
        console.print(Panel(
            f"[bold green]PASS: All {result.passed_checks} semantic, evidence, and coverage integrity checks passed![/bold green]",
            border_style="green"
        ))
        sys.exit(0)
    elif result.status == "WARNING":
        console.print(Panel(
            f"[bold yellow]WARNING: Passed {result.passed_checks} checks with {result.warning_checks} warning(s).[/bold yellow]",
            border_style="yellow"
        ))
        sys.exit(0)
    else:
        console.print(Panel(
            f"[bold red]FAIL: Case validation failed with {result.failed_checks} error(s). Please review the table above.[/bold red]",
            border_style="red"
        ))
        sys.exit(1)


def cmd_lab(action: str = "check", output_path: Optional[str] = None, target_dir: Optional[str] = None, mode: str = "ISOLATED"):
    """Manages analysis lab auditing, provisioning, and network verification."""
    from lab.windows.detector import WindowsLabDetector
    from lab.windows.provisioner import WindowsLabProvisioner
    from lab.network.verifier import NetworkLabVerifier, NetworkPolicyMode

    if action == "provision":
        script = WindowsLabProvisioner.generate_powershell_script()
        dest_path = None
        if output_path:
            dest_path = Path(output_path)
        elif target_dir:
            dest_path = Path(target_dir) / "provision_0206_lab.ps1"

        if dest_path:
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_text(script, encoding="utf-8")
            console.print(f"[bold green]✔ Provisioning script generated at:[/bold green] [cyan]{dest_path.resolve()}[/cyan]")
        else:
            console.print(script)
    elif action == "verify-net":
        try:
            pol_mode = NetworkPolicyMode(mode.upper())
        except ValueError:
            pol_mode = NetworkPolicyMode.ISOLATED
        console.print(f"[*] Verifying network policy: [cyan]{pol_mode.value}[/cyan] ...")
        res = NetworkLabVerifier.verify_network_policy(pol_mode)
        console.print(f"  Interface: [bold]{res.interface}[/bold] (IP: {res.ip_address})")
        console.print(f"  Gateway:   {res.default_gateway or 'None'}")
        console.print(f"  DNS Mode:  {res.dns_mode}")
        color = "green" if "VERIFIED" in res.verification_status else "red"
        console.print(f"  Status:    [{color}]{res.verification_status}[/{color}] - {res.details}")
    else:  # check
        console.print("[*] Auditing Windows REM Lab tools & environment...")
        run_doctor(console)


def cmd_sandbox_smoke_test(backend_name: str = "virtualbox", config: Optional[SandboxGuestConfig] = None):
    """
    Executes a harmless VM smoke test using repository-generated harmless fixture.
    Refuses arbitrary sample paths.
    If real VirtualBox VM is not available, reports REAL_VM_SMOKE_TEST=NOT_RUN.
    """
    cfg = config or SandboxGuestConfig()
    backend_type = (backend_name or cfg.backend or "virtualbox").lower()
    console.print(Panel(
        f"[bold cyan]🧪 0206 Harmless Sandbox VM Smoke Test: {backend_type.upper()}[/bold cyan]\n"
        f"Target VM: [cyan]{cfg.vm_name}[/cyan] | Snapshot: [cyan]{cfg.snapshot_name}[/cyan]\n"
        "[dim]Safety Guarantee: Refuses arbitrary sample paths; strictly executes benign test fixture.[/dim]",
        border_style="cyan"
    ))

    if backend_type != "virtualbox":
        console.print(f"[yellow]Backend '{backend_type}' is not supported for live VM smoke testing.[/yellow]")
        console.print("[bold yellow]REAL_VM_SMOKE_TEST=NOT_RUN[/bold yellow]")
        return

    from sandbox.backends.virtualbox import VirtualBoxSandboxBackend
    from sandbox.controller import SandboxController

    vbox = VirtualBoxSandboxBackend(config=cfg)
    if not vbox.is_available():
        console.print("[yellow]VBoxManage CLI is not installed or available on this host.[/yellow]")
        console.print("[bold yellow]REAL_VM_SMOKE_TEST=NOT_RUN[/bold yellow]")
        return

    vm_rec = vbox.verify_vm()
    if not vm_rec.is_success():
        console.print(f"[yellow]Configured VM '{cfg.vm_name}' not available on host: {vm_rec.details}[/yellow]")
        console.print("[bold yellow]REAL_VM_SMOKE_TEST=NOT_RUN[/bold yellow]")
        return

    snap_rec = vbox.verify_baseline()
    if not snap_rec.is_success():
        console.print(f"[yellow]Baseline snapshot '{cfg.snapshot_name}' not available on VM: {snap_rec.details}[/yellow]")
        console.print("[bold yellow]REAL_VM_SMOKE_TEST=NOT_RUN[/bold yellow]")
        return

    # Real VM is present! Use only harmless test PE fixture
    fixture_path = Path(__file__).resolve().parent.parent / "tests" / "sample_benign_triage.exe"
    if not fixture_path.exists():
        try:
            from tests.generate_test_artifacts import generate_benign_pe
            fixture_path = generate_benign_pe()
        except Exception:
            pass

    if not fixture_path.exists():
        console.print("[yellow]Harmless test fixture could not be located or built.[/yellow]")
        console.print("[bold yellow]REAL_VM_SMOKE_TEST=NOT_RUN[/bold yellow]")
        return

    console.print(f"[*] Executing harmless smoke test with repository benign fixture: [cyan]{fixture_path.name}[/cyan] ...")
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td) / "smoke_test_case"
        out_dir.mkdir(parents=True, exist_ok=True)
        controller = SandboxController(config=cfg, backend_instance=vbox)
        trace = controller.run_safe_session(str(fixture_path), str(out_dir / "sandbox"))

        if trace.status not in (SandboxStatus.COMPLETED, SandboxStatus.PARTIAL) or trace.revert_status != ActionStatus.VERIFIED.value:
            console.print(f"[bold red]Smoke test failed: {trace.errors}[/bold red]")
            console.print("[bold red]REAL_VM_SMOKE_TEST=FAILED[/bold red]")
            sys.exit(1)

        console.print("[bold green]✔ Live VM smoke test completed successfully![/bold green]")
        console.print("[bold green]REAL_VM_SMOKE_TEST=PASSED[/bold green]")


def resolve_sandbox_config(args) -> SandboxGuestConfig:
    """Loads and resolves SandboxGuestConfig from config files and explicit CLI flags."""
    cfg_file = getattr(args, "sandbox_config", None)
    cfg = SandboxGuestConfig.load_config(cfg_file)
    if getattr(args, "vm_name", None):
        cfg.vm_name = args.vm_name
    if getattr(args, "snapshot_name", None):
        cfg.snapshot_name = args.snapshot_name
    if getattr(args, "guest_username", None):
        cfg.guest_username = args.guest_username
    if getattr(args, "guest_password_env", None):
        cfg.guest_password_env = args.guest_password_env
    if getattr(args, "network_mode", None):
        try:
            cfg.network_mode = SandboxNetworkMode(args.network_mode.upper())
        except ValueError:
            pass
    if getattr(args, "execution_timeout", None):
        try:
            cfg.execution_timeout_seconds = int(args.execution_timeout)
        except (ValueError, TypeError):
            pass
    if getattr(args, "vbox_user_home", None):
        cfg.vbox_user_home = args.vbox_user_home
    return cfg


def display_findings_table(findings: list):
    """Displays technical findings with grounded evidence IDs."""
    if not findings:
        return
    f_table = Table(title="📑 Derived Technical Findings", show_header=True, header_style="bold magenta")
    f_table.add_column("ID", style="bold cyan", width=8)
    f_table.add_column("Status", width=15)
    f_table.add_column("Domain", style="yellow", width=22)
    f_table.add_column("Title & Inferences", style="white")
    f_table.add_column("Grounded Evidence", style="dim", width=18)

    for f in findings:
        raw_status = getattr(f, "status", getattr(f, "evidence_level", "CAPABILITY"))
        status_val = getattr(raw_status, "value", str(raw_status))
        status_str = f"[bold green]{status_val}[/bold green]" if "CONFIRMED" in str(status_val) else f"[cyan]{status_val}[/cyan]"
        eids = ", ".join(f.source_evidence_ids[:3]) + ("..." if len(f.source_evidence_ids) > 3 else "")
        raw_dom = getattr(f, "domain", getattr(f, "category", "PE"))
        dom_val = getattr(raw_dom, "value", str(raw_dom))
        f_table.add_row(f.finding_id, status_str, dom_val, f.title, eids or "None")
    console.print(f_table)


def display_coverage_table(coverage_file: Optional[Path]):
    """Displays canonical analysis coverage matrix."""
    table = Table(title="📊 Analysis Coverage", show_header=True, header_style="bold cyan")
    table.add_column("Analysis Domain", style="bold white", width=22)
    table.add_column("Status", width=16)
    table.add_column("Scope / Reason", style="dim")

    domain_data = {}
    coverage_reasons = {}
    if coverage_file and coverage_file.exists():
        try:
            with open(coverage_file, "r", encoding="utf-8") as f:
                c_json = json.load(f)
                domain_data = c_json.get("domain_coverage", {}) or {k: v for k, v in c_json.items() if isinstance(v, str)}
                coverage_reasons = c_json.get("coverage_reasons", {})
        except Exception:
            pass

    if domain_data:
        for dom, st in domain_data.items():
            color = "green" if st == "COMPLETED" else ("yellow" if st == "PARTIAL" else "dim")
            reason = coverage_reasons.get(dom, "Automated triage evaluation")
            table.add_row(dom, f"[{color}]{st}[/{color}]", reason)
    else:
        defaults = [
            ("PE Static", "COMPLETED", "PE structure and metadata analyzed"),
            ("Code Triage", "COMPLETED", "Capstone disassembly triage performed"),
            ("Reputation", "SKIPPED_OFFLINE", "External reputation lookup skipped in offline mode"),
            ("Network", "NOT_ANALYZED", "No PCAP artifact provided"),
            ("Process", "NOT_ANALYZED", "No Procmon artifact provided"),
            ("Memory", "NOT_AVAILABLE", "Memory acquisition not performed"),
            ("Unpacking", "NOT_ANALYZED", "Dynamic unpacking not engaged in profile"),
            ("Anti-Analysis", "NOT_ANALYZED", "Dedicated anti-analysis not engaged in profile"),
        ]
        for dom, st, reason in defaults:
            color = "green" if st == "COMPLETED" else "dim"
            table.add_row(dom, f"[{color}]{st}[/{color}]", reason)

    console.print(table)


def display_reputation_summary(store: EvidenceStore):
    """Displays truthful summary of reputation stage output (P0.4)."""
    rep_records = store.find(source_type="REPUTATION")
    if not rep_records:
        console.print(Panel(
            "Provider: [dim]None[/dim] | Detections: [dim]N/A[/dim] | Lookup Status: [dim]NOT_ANALYZED[/dim]",
            title="🔍 Reputation Assessment",
            border_style="dim"
        ))
        return

    status_rec = next((r for r in rep_records if r.field == "lookup_status"), rep_records[0])
    ratio_rec = next((r for r in rep_records if r.field == "detection_ratio"), rep_records[0])
    prov = status_rec.provenance or ratio_rec.provenance or {}

    st = status_rec.value or prov.get("lookup_status") or prov.get("status") or "NOT_CHECKED"
    positives = prov.get("positives", 0)
    total = prov.get("total", 0)
    provider_name = status_rec.extractor or "VirusTotal"

    if st in ("NOT_CHECKED", "SKIPPED_OFFLINE"):
        console.print(Panel(
            f"Provider: [bold cyan]{provider_name}[/bold cyan] | "
            f"Detections: [dim]N/A (External lookup skipped in offline mode / no API key)[/dim] | "
            f"Lookup Status: [dim]{st}[/dim]",
            title="🔍 Reputation Assessment",
            border_style="dim"
        ))
    elif st == "NOT_FOUND":
        console.print(Panel(
            f"Provider: [bold cyan]{provider_name}[/bold cyan] | "
            f"Detections: [yellow]NOT_FOUND[/yellow] | "
            f"Lookup Status: [yellow]NOT_FOUND[/yellow] ([italic]Absence of threat intel != Clean[/italic])",
            title="🔍 Reputation Assessment",
            border_style="yellow"
        ))
    elif st == "LOOKUP_FAILED":
        console.print(Panel(
            f"Provider: [bold cyan]{provider_name}[/bold cyan] | "
            f"Detections: [yellow]N/A[/yellow] | "
            f"Lookup Status: [yellow]LOOKUP_FAILED[/yellow]",
            title="🔍 Reputation Assessment",
            border_style="yellow"
        ))
    else:
        color = "red" if positives >= 5 else ("yellow" if positives >= 1 else "green")
        det_ratio = f"{positives}/{total}" if total > 0 else "0/0"
        console.print(Panel(
            f"Provider: [bold cyan]{provider_name}[/bold cyan] | "
            f"Detections: [{color}]{det_ratio}[/{color}] | "
            f"Lookup Status: [bold]{st}[/bold]",
            title="🔍 Reputation Assessment",
            border_style=color
        ))


def run_analyze_cli(
    sample_path: Optional[str] = None,
    pcap_path: Optional[str] = None,
    procmon_path: Optional[str] = None,
    regshot_path: Optional[str] = None,
    output_dir_str: Optional[str] = None,
    template_path_str: Optional[str] = None,
    profile_str: str = "standard",
    privacy_mode_str: str = "strict",
    offline_mode: bool = False,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    yara_rules: Optional[str] = None,
    backend: str = "memory",
    adaptive: bool = False,
    portable: bool = False,
    export_raw_evidence: bool = False,
    detonate: bool = False,
    sandbox_backend: Optional[str] = None,
    sandbox_config: Optional[SandboxGuestConfig] = None,
    quiet: bool = False,
    json_output: bool = False,
    no_color: bool = False
):
    """Executes the analysis using the thin AnalysisOrchestrator."""
    if no_color:
        console.no_color = True

    orchestrator = AnalysisOrchestrator()

    if quiet or json_output:
        try:
            result: OrchestrationResult = orchestrator.run(
                sample_path=sample_path,
                pcap_path=pcap_path,
                procmon_path=procmon_path,
                regshot_path=regshot_path,
                output_dir=output_dir_str,
                profile=profile_str,
                privacy_mode=privacy_mode_str,
                offline=offline_mode,
                api_key=api_key,
                model=model,
                template_path=template_path_str,
                yara_rules=yara_rules,
                backend=backend,
                adaptive=adaptive,
                portable=portable,
                export_raw_evidence=export_raw_evidence,
                step_callback=None,
                detonate=detonate,
                sandbox_backend=sandbox_backend,
                sandbox_config=sandbox_config
            )
        except Exception as e:
            if json_output:
                print(json.dumps({"error": str(e)}))
            else:
                sys.stderr.write(f"Analysis failed: {e}\n")
            sys.exit(1)

        if json_output:
            if result.report_json.exists():
                print(result.report_json.read_text(encoding="utf-8"))
            else:
                print(json.dumps(result.assessment.model_dump(), indent=2))
            return
        elif quiet:
            print(f"Analysis complete: {result.case_id}")
            print(f"Threat Score: {result.assessment.threat_score}/100 ({result.assessment.threat_level})")
            print(f"Classification: {result.assessment.classification}")
            print(f"Output: {result.output_dir.resolve()}")
            return

    # Interactive rich console rendering
    result: Optional[OrchestrationResult] = None
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[bold cyan]Initializing Triage Pipeline...", total=14)

        def step_callback(step_name: str, step_num: int):
            progress.update(task, completed=step_num, description=f"[bold cyan]{step_name}")

        try:
            result = orchestrator.run(
                sample_path=sample_path,
                pcap_path=pcap_path,
                procmon_path=procmon_path,
                regshot_path=regshot_path,
                output_dir=output_dir_str,
                profile=profile_str,
                privacy_mode=privacy_mode_str,
                offline=offline_mode,
                api_key=api_key,
                model=model,
                template_path=template_path_str,
                yara_rules=yara_rules,
                backend=backend,
                adaptive=adaptive,
                portable=portable,
                export_raw_evidence=export_raw_evidence,
                step_callback=step_callback,
                detonate=detonate,
                sandbox_backend=sandbox_backend,
                sandbox_config=sandbox_config
            )
            progress.update(task, completed=14, description="[bold green]Analysis Complete!")
        except Exception as e:
            console.print(f"\n[bold red][!] Analysis Failed:[/bold red] {e}")
            sys.exit(1)

    # ---------------- UI Presentation ----------------
    console.print("\n")
    # 1. Sample info (P0.6: Always display actual filename)
    meta_recs = result.evidence_store.find(source_type="FILE_METADATA")
    meta_dict = {r.field: r.value for r in meta_recs} if meta_recs else {}
    sample_name = result.manifest.sample_filename or meta_dict.get("filename")
    if not sample_name or sample_name == "Unknown":
        if meta_recs:
            sample_name = meta_recs[0].source_artifact or "sample.exe"
        else:
            sample_name = "sample.exe"

    file_size_val = result.manifest.sample_size_bytes or meta_dict.get("file_size") or 0
    sha256_val = result.manifest.sample_hashes.get("sha256") or meta_dict.get("sha256") or "N/A"

    console.print(Panel(
        f"Filename: [bold white]{sample_name}[/bold white] | "
        f"Size: {file_size_val:,} bytes | "
        f"SHA256: [cyan]{sha256_val}[/cyan]",
        title="🎯 Target Sample",
        border_style="cyan"
    ))

    # 2. Reputation
    display_reputation_summary(result.evidence_store)
    console.print("")

    # 3. Findings table
    display_findings_table(result.findings)
    console.print("")

    # 4. Analysis Coverage table
    display_coverage_table(result.coverage_json)
    console.print("")

    # 5. Threat Assessment Panel
    assessment = result.assessment
    level = assessment.threat_level
    badge_colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow", "LOW": "blue"}
    color = badge_colors.get(level, "green")

    panel_content = (
        f"[{color}]Authoritative Assessment: {level} (Score: {assessment.threat_score}/100)[/{color}]\n"
        f"[bold white]Classification:[/bold white] {assessment.classification}\n"
        f"[bold white]Classification Confidence:[/bold white] {getattr(assessment, 'classification_confidence', getattr(assessment, 'confidence', 0.0)):.2f}\n"
        f"[bold white]Analysis Confidence:[/bold white] {getattr(assessment, 'analysis_confidence', 1.0):.2f}\n\n"
        f"[italic]{assessment.summary}[/italic]\n\n"
        f"[bold cyan]Grounding:[/bold cyan] Grounded in {len(result.evidence_store)} verified EvidenceRecords and {len(result.findings)} Findings."
    )
    console.print(Panel(panel_content, title="🛡️ 0206 Authoritative Assessment", border_style=color))

    # 6. Deliverables Summary Panel
    deliverables_text = (
        f"[bold green]✔ Analysis Complete & Deliverables Exported![/bold green]\n\n"
        f"  📁 Output Directory: [cyan]{result.output_dir.resolve()}[/cyan]\n"
        f"  📄 Machine JSON:     [white]{result.report_json.name}[/white]\n"
        f"  📝 Markdown Report:  [white]{result.report_md.name}[/white]\n"
        f"  📘 Word Document:    [white]{result.report_docx.name}[/white]\n"
        f"  📑 Audit Manifest:   [white]{result.manifest_json.name}[/white]\n"
        f"  🔒 Manifest SHA256:  [white]{result.manifest_sha256.name}[/white]\n"
        f"  🔍 Evidence Store:   [white]{result.evidence_json.name}[/white]\n"
        f"  ⚖️ Findings Catalog: [white]{result.findings_json.name}[/white]\n"
        f"  📊 Coverage Matrix:  [white]{(result.coverage_json.name if result.coverage_json else 'coverage.json')}[/white]"
    )
    if result.evidence_raw_json:
        deliverables_text += f"\n  ⚠️ Raw Evidence:    [yellow]{result.evidence_raw_json.name}[/yellow]"

    console.print(Panel(deliverables_text, border_style="green", title="📦 Session Deliverables"))


def main():
    parser = argparse.ArgumentParser(
        description=f"{ENGINE_NAME}: Independent, Local-First Malware Analysis & Reporting Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Subcommand: analyze
    p_analyze = subparsers.add_parser("analyze", help="Execute triage and generate reports")
    p_analyze.add_argument("target", nargs="?", type=str, help="Target PE binary file (.exe, .dll)")
    p_analyze.add_argument("--sample", "-s", type=str, help="Path to sample PE binary")
    p_analyze.add_argument("--pcap", "-p", type=str, help="Path to network capture trace (.pcap)")
    p_analyze.add_argument("--procmon", "-m", type=str, help="Path to Process Monitor CSV log (.csv)")
    p_analyze.add_argument("--regshot", "-r", type=str, help="Path to Regshot diff log (.txt)")
    p_analyze.add_argument("--output-dir", "-o", type=str, help="Output destination folder")
    p_analyze.add_argument("--profile", type=str, choices=["minimal", "basic", "standard", "advanced", "full"], default="standard", help="Analysis profile")
    p_analyze.add_argument("--template", "-t", type=str, help="Path to custom DOCX report template")
    p_analyze.add_argument("--privacy", type=str, choices=["strict", "standard", "none"], default="strict", help="Privacy redaction mode")
    p_analyze.add_argument("--offline", action="store_true", help="Force offline deterministic engine (no remote AI/API calls)")
    p_analyze.add_argument("--adaptive", action="store_true", help="Adaptive mode: dynamically detect environment and run available tools")
    p_analyze.add_argument("--portable", action="store_true", help="Portable mode: offline, zero proprietary tools, sanitized local paths")
    p_analyze.add_argument("--yara-rules", type=str, help="Path to custom YARA rules file (.yar/.yara)")
    p_analyze.add_argument("--evidence-backend", type=str, choices=["memory", "sqlite"], default=None, help="Evidence Store backend storage (memory, sqlite)")
    p_analyze.add_argument("--backend", type=str, choices=["memory", "sqlite"], default=None, help="[DEPRECATED] Alias for --evidence-backend")
    p_analyze.add_argument("--detonate", action="store_true", default=False, help="Request live sample execution inside configured sandbox VM")
    p_analyze.add_argument("--sandbox", type=str, choices=["virtualbox", "qemu", "vmware", "external", "builtin", "builtin_safe"], default="virtualbox", help="Sandbox backend for live detonation (default: virtualbox)")
    p_analyze.add_argument("--api-key", type=str, help="[DEPRECATED] API key for remote LLM provider. Prefer OPENAI_API_KEY / ANTHROPIC_API_KEY env vars.")
    p_analyze.add_argument("--model", type=str, default=None, help="LLM model name (defaults to provider specific default)")
    p_analyze.add_argument("--export-raw-evidence", action="store_true", help="Export unredacted raw internal evidence to evidence.raw.json")
    p_analyze.add_argument("--quiet", "-q", action="store_true", help="Quiet output (suppress banner, progress bars, non-critical logs)")
    p_analyze.add_argument("--json", action="store_true", help="Emit report results as JSON to stdout")
    p_analyze.add_argument("--no-color", action="store_true", help="Disable colored / ANSI output")
    # Sandbox configuration options
    p_analyze.add_argument("--sandbox-config", type=str, default=None, help="Path to sandbox configuration TOML file")
    p_analyze.add_argument("--vm-name", type=str, default=None, help="Sandbox VM name override")
    p_analyze.add_argument("--snapshot-name", type=str, default=None, help="Sandbox baseline snapshot name override")
    p_analyze.add_argument("--guest-username", type=str, default=None, help="Sandbox guest OS username override")
    p_analyze.add_argument("--guest-password-env", type=str, default=None, help="Sandbox guest password environment variable name")
    p_analyze.add_argument("--network-mode", type=str, choices=["ISOLATED", "HOST_ONLY", "SIMULATED_INTERNET"], default=None, help="Sandbox network mode")
    p_analyze.add_argument("--execution-timeout", type=int, default=None, help="Sandbox execution timeout in seconds")
    p_analyze.add_argument("--vbox-user-home", type=str, default=None, help="VirtualBox configuration directory (VBOX_USER_HOME)")

    # Subcommand: doctor
    subparsers.add_parser("doctor", help="Run capability diagnostics and dependency check")

    # Subcommand: sandbox
    p_sandbox = subparsers.add_parser("sandbox", help="Manage and audit dynamic detonation sandbox environments")
    p_sandbox.add_argument("action", choices=["doctor", "smoke-test"], nargs="?", default="doctor", help="Sandbox action (doctor, smoke-test)")
    p_sandbox.add_argument("--backend", type=str, default="virtualbox", choices=["virtualbox", "qemu", "vmware", "external", "builtin", "builtin_safe"], help="Sandbox hypervisor backend")
    p_sandbox.add_argument("--sandbox-config", type=str, default=None, help="Path to sandbox configuration TOML file")
    p_sandbox.add_argument("--vm-name", type=str, default=None, help="Sandbox VM name override")
    p_sandbox.add_argument("--snapshot-name", type=str, default=None, help="Sandbox baseline snapshot name override")
    p_sandbox.add_argument("--guest-username", type=str, default=None, help="Sandbox guest OS username override")
    p_sandbox.add_argument("--guest-password-env", type=str, default=None, help="Sandbox guest password environment variable name")
    p_sandbox.add_argument("--network-mode", type=str, choices=["ISOLATED", "HOST_ONLY", "SIMULATED_INTERNET"], default=None, help="Sandbox network mode")
    p_sandbox.add_argument("--execution-timeout", type=int, default=None, help="Sandbox execution timeout in seconds")
    p_sandbox.add_argument("--vbox-user-home", type=str, default=None, help="VirtualBox configuration directory (VBOX_USER_HOME)")

    # Subcommand: capabilities
    subparsers.add_parser("capabilities", help="List detected Tier 1, 2, and 3 capabilities")

    # Subcommand: selftest
    subparsers.add_parser("selftest", help="Run automated offline platform self-tests")

    # Subcommand: validate-template
    p_val = subparsers.add_parser("validate-template", help="Validate a DOCX report template")
    p_val.add_argument("template_path", type=str, help="Path to DOCX template file")

    # Subcommand: manifest
    p_man = subparsers.add_parser("manifest", help="Inspect and display an analysis manifest")
    p_man.add_argument("manifest_path", nargs="?", type=str, help="Path to analysis_manifest.json")

    # Subcommand: verify-case (P1.15)
    p_ver = subparsers.add_parser("verify-case", help="Cryptographically verify case deliverables and manifest lineage")
    p_ver.add_argument("case_path", nargs="?", type=str, help="Path to case directory or analysis_manifest.json")

    # Subcommand: validate-case
    p_val_case = subparsers.add_parser("validate-case", help="Perform comprehensive semantic validation on case directory")
    p_val_case.add_argument("case_path", type=str, help="Path to case directory to validate")

    # Subcommand: lab
    p_lab = subparsers.add_parser("lab", help="Manage and audit analysis lab workstation & network")
    p_lab.add_argument("action", choices=["check", "provision", "verify-net"], nargs="?", default="check", help="Lab action")
    p_lab.add_argument("--output", "-o", type=str, help="Destination file for generated provisioning script")
    p_lab.add_argument("--target-dir", type=str, default=None, help="Destination directory for generated provisioning script")
    p_lab.add_argument("--mode", type=str, default="ISOLATED", choices=["ISOLATED", "HOST_ONLY", "SIMULATED_INTERNET"], help="Expected network mode")

    # Backward compatibility: Top-level arguments for direct `0206 --sample ...` or `0206 sample.exe`
    parser.add_argument("direct_target", nargs="?", type=str, help=argparse.SUPPRESS)
    parser.add_argument("--sample", "-s", type=str, help="Target PE binary")
    parser.add_argument("--pcap", "-p", type=str, help="Network capture trace")
    parser.add_argument("--procmon", "-m", type=str, help="Procmon CSV log")
    parser.add_argument("--regshot", "-r", type=str, help="Regshot diff log")
    parser.add_argument("--output", "-o", type=str, help="Output path/directory")
    parser.add_argument("--output-dir", type=str, help="Output path/directory")
    parser.add_argument("--profile", type=str, choices=["minimal", "basic", "standard", "advanced", "full"], default="standard")
    parser.add_argument("--template", "-t", type=str, help="Custom DOCX template")
    parser.add_argument("--privacy", type=str, choices=["strict", "standard", "none"], default="strict")
    parser.add_argument("--offline", action="store_true", help="Force offline mode")
    parser.add_argument("--adaptive", action="store_true", help="Adaptive mode: dynamically detect environment and run available tools")
    parser.add_argument("--portable", action="store_true", help="Portable mode: offline, zero proprietary tools, sanitized local paths")
    parser.add_argument("--yara-rules", type=str, help="Path to custom YARA rules file (.yar/.yara)")
    parser.add_argument("--evidence-backend", type=str, choices=["memory", "sqlite"], default=None, help="Evidence Store backend storage")
    parser.add_argument("--backend", type=str, choices=["memory", "sqlite"], default=None, help="[DEPRECATED] Alias for --evidence-backend")
    parser.add_argument("--detonate", action="store_true", default=False, help="Request live sample execution inside configured sandbox VM")
    parser.add_argument("--sandbox", type=str, choices=["virtualbox", "qemu", "vmware", "external", "builtin", "builtin_safe"], default="virtualbox", help="Sandbox backend for live detonation")
    parser.add_argument("--sandbox-config", type=str, default=None, help="Path to sandbox configuration TOML file")
    parser.add_argument("--vm-name", type=str, default=None, help="Sandbox VM name override")
    parser.add_argument("--snapshot-name", type=str, default=None, help="Sandbox baseline snapshot name override")
    parser.add_argument("--guest-username", type=str, default=None, help="Sandbox guest OS username override")
    parser.add_argument("--guest-password-env", type=str, default=None, help="Sandbox guest password environment variable name")
    parser.add_argument("--network-mode", type=str, choices=["ISOLATED", "HOST_ONLY", "SIMULATED_INTERNET"], default=None, help="Sandbox network mode")
    parser.add_argument("--execution-timeout", type=int, default=None, help="Sandbox execution timeout in seconds")
    parser.add_argument("--vbox-user-home", type=str, default=None, help="VirtualBox configuration directory (VBOX_USER_HOME)")
    parser.add_argument("--api-key", type=str, help="[DEPRECATED] API key for remote LLM provider. Prefer OPENAI_API_KEY / ANTHROPIC_API_KEY env vars.")
    parser.add_argument("--model", type=str, default=None)
    parser.add_argument("--export-raw-evidence", action="store_true", help="Export unredacted raw internal evidence to evidence.raw.json")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet output")
    parser.add_argument("--json", action="store_true", help="Emit report results as JSON to stdout")
    parser.add_argument("--no-color", action="store_true", help="Disable colored / ANSI output")

    args = parser.parse_args()

    is_quiet_or_json = getattr(args, "quiet", False) or getattr(args, "json", False)
    if not is_quiet_or_json:
        print_banner()

    if getattr(args, "api_key", None):
        import warnings
        warnings.warn(
            "Passing secrets through CLI arguments may expose them through shell history or process inspection. Prefer environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY).",
            DeprecationWarning,
            stacklevel=2
        )
        if not is_quiet_or_json:
            console.print("[yellow][!] Warning: Passing secrets through CLI arguments may expose them through shell history or process inspection. Prefer environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY).[/yellow]")

    if getattr(args, "no_color", False):
        console.no_color = True

    # Route Subcommands
    if args.subcommand == "doctor":
        cmd_doctor()
        return
    elif args.subcommand == "capabilities":
        cmd_capabilities()
        return
    elif args.subcommand == "selftest":
        cmd_selftest()
        return
    elif args.subcommand == "validate-template":
        cmd_validate_template(args.template_path)
        return
    elif args.subcommand == "manifest":
        cmd_manifest(args.manifest_path)
        return
    elif args.subcommand == "verify-case":
        cmd_verify_case(args.case_path)
        return
    elif args.subcommand == "validate-case":
        cmd_validate_case(args.case_path)
        return
    elif args.subcommand == "lab":
        cmd_lab(args.action, args.output, getattr(args, "target_dir", None), args.mode)
        return
    elif args.subcommand == "sandbox":
        action = getattr(args, "action", "doctor")
        s_cfg = resolve_sandbox_config(args)
        if action == "smoke-test":
            cmd_sandbox_smoke_test(backend_name=args.backend, config=s_cfg)
            return
        elif action == "doctor":
            success = run_sandbox_doctor(console, backend_name=args.backend, config=s_cfg)
            if not success:
                sys.exit(1)
            return
    elif args.subcommand == "analyze":
        sample = args.target or args.sample
        ev_backend = getattr(args, "evidence_backend", None) or getattr(args, "backend", None) or "memory"
        if getattr(args, "backend", None) and not is_quiet_or_json:
            console.print("[yellow][!] Warning: '--backend' is deprecated; prefer '--evidence-backend'.[/yellow]")
        s_cfg = resolve_sandbox_config(args)
        run_analyze_cli(
            sample_path=sample,
            pcap_path=args.pcap,
            procmon_path=args.procmon,
            regshot_path=args.regshot,
            output_dir_str=args.output_dir,
            template_path_str=args.template,
            profile_str=args.profile,
            privacy_mode_str=args.privacy,
            offline_mode=args.offline,
            api_key=args.api_key,
            model=args.model,
            yara_rules=args.yara_rules,
            backend=ev_backend,
            adaptive=args.adaptive,
            portable=args.portable,
            export_raw_evidence=args.export_raw_evidence,
            detonate=getattr(args, "detonate", False),
            sandbox_backend=getattr(args, "sandbox", "virtualbox"),
            sandbox_config=s_cfg,
            quiet=args.quiet,
            json_output=args.json,
            no_color=args.no_color
        )
        return

    # Direct top-level flags (backward compatibility)
    sample = args.direct_target or args.sample
    if sample or args.pcap or args.procmon:
        out_dir = args.output_dir or args.output
        if out_dir and out_dir.endswith(".docx"):
            out_dir = str(Path(out_dir).parent)
        ev_backend = getattr(args, "evidence_backend", None) or getattr(args, "backend", None) or "memory"
        s_cfg = resolve_sandbox_config(args)
        run_analyze_cli(
            sample_path=sample,
            pcap_path=args.pcap,
            procmon_path=args.procmon,
            regshot_path=args.regshot,
            output_dir_str=out_dir,
            template_path_str=args.template,
            profile_str=args.profile,
            privacy_mode_str=args.privacy,
            offline_mode=args.offline,
            api_key=args.api_key,
            model=args.model,
            yara_rules=args.yara_rules,
            backend=ev_backend,
            adaptive=args.adaptive,
            portable=args.portable,
            export_raw_evidence=args.export_raw_evidence,
            detonate=getattr(args, "detonate", False),
            sandbox_backend=getattr(args, "sandbox", "virtualbox"),
            sandbox_config=s_cfg,
            quiet=args.quiet,
            json_output=args.json,
            no_color=args.no_color
        )
    else:
        cmd_doctor()
        console.print("\n[dim]Run '0206 analyze --help' or '0206 --help' to see analysis options.[/dim]")


if __name__ == "__main__":
    main()
