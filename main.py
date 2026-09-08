#!/usr/bin/env python3
"""
0206: Modular, Evidence-Grounded Malware Triage & Analysis Platform
Thin CLI entry point with rich subcommands:
  0206 analyze <sample> [--pcap <pcap>] [--procmon <csv>] [--profile standard] [--offline]
  0206 doctor
  0206 capabilities
  0206 validate-template <template.docx>
  0206 manifest [analysis_manifest.json]
  0206 selftest
"""
import sys
import os
import json
import argparse
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text

from config import ENGINE_NAME, ENGINE_VERSION
from core.orchestrator import AnalysisOrchestrator, OrchestrationResult
from core.doctor import run_doctor
from core.selftest import run_selftest
from report.template_validator import TemplateValidator

console = Console()


def print_banner():
    """Renders the 0206 platform banner."""
    banner_text = Text()
    banner_text.append(f"⚡ {ENGINE_NAME} ⚡\n", style="bold cyan")
    banner_text.append(f"Modular, Evidence-Grounded Malware Triage & Analysis Platform (v{ENGINE_VERSION})\n", style="italic white")
    banner_text.append("Evidence Store • Finding Engine • Multi-factor Beacons • Grounded Reporting", style="dim green")
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
    valid, warnings = TemplateValidator.validate_sans_style_template(p)
    if valid:
        console.print("[bold green]✔ Template is valid and compatible with SANS-style report adapter.[/bold green]")
        if warnings:
            for w in warnings:
                console.print(f"  [yellow]Warning:[/yellow] {w}")
    else:
        console.print("[bold red]✗ Template validation failed:[/bold red]")
        for w in warnings:
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


def display_findings_table(findings: list):
    """Displays technical findings with grounded evidence IDs."""
    if not findings:
        return
    f_table = Table(title="📑 Derived Technical Findings", show_header=True, header_style="bold magenta")
    f_table.add_column("ID", style="bold cyan", width=8)
    f_table.add_column("Level", width=15)
    f_table.add_column("Category", style="yellow", width=22)
    f_table.add_column("Title & Inferences", style="white")
    f_table.add_column("Grounded Evidence", style="dim", width=18)

    for f in findings:
        lvl = f.evidence_level
        lvl_str = f"[bold green]{lvl}[/bold green]" if lvl == "OBSERVED" else f"[cyan]{lvl}[/cyan]"
        eids = ", ".join(f.source_evidence_ids[:3]) + ("..." if len(f.source_evidence_ids) > 3 else "")
        f_table.add_row(f.finding_id, lvl_str, f.category, f.title, eids or "None")
    console.print(f_table)


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
    model: str = "gpt-4o"
):
    """Executes the analysis using the thin AnalysisOrchestrator."""
    orchestrator = AnalysisOrchestrator()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Initializing Triage Pipeline...", total=12)

        def step_callback(msg: str, step: int):
            progress.update(task, completed=step, description=f"[cyan]{msg}")

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
                step_callback=step_callback
            )
            progress.update(task, completed=12, description="[bold green]Analysis Complete!")
        except Exception as e:
            console.print(f"\n[bold red][!] Analysis Failed:[/bold red] {e}")
            sys.exit(1)

    # ---------------- UI Presentation ----------------
    console.print("\n")
    display_findings_table(result.findings)
    console.print("\n")

    # Threat Assessment Panel
    assessment = result.assessment
    level = assessment.threat_level
    badge_colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow", "LOW": "blue"}
    color = badge_colors.get(level, "green")

    panel_content = (
        f"[{color}]Assessment: {level} (Score: {assessment.threat_score}/100)[/{color}]\n"
        f"[bold white]Classification:[/bold white] {assessment.classification}\n\n"
        f"[italic]{assessment.summary}[/italic]\n\n"
        f"[bold cyan]Grounding:[/bold cyan] Grounded in {len(result.evidence_store)} verified EvidenceRecords and {len(result.findings)} Findings."
    )
    console.print(Panel(panel_content, title="🛡️ 0206 Triage Assessment", border_style=color))

    # Deliverables Summary Panel
    console.print(Panel(
        f"[bold green]✔ Analysis Complete & Deliverables Exported![/bold green]\n\n"
        f"  📁 Output Directory: [cyan]{result.output_dir.resolve()}[/cyan]\n"
        f"  📄 Machine JSON:     [white]{result.report_json.name}[/white]\n"
        f"  📝 Markdown Report:  [white]{result.report_md.name}[/white]\n"
        f"  📘 Word Document:    [white]{result.report_docx.name}[/white]\n"
        f"  📑 Audit Manifest:   [white]{result.manifest_json.name}[/white]\n"
        f"  🔍 Evidence Store:   [white]{result.evidence_json.name}[/white]\n"
        f"  ⚖️ Findings Catalog: [white]{result.findings_json.name}[/white]",
        border_style="green",
        title="📦 Session Deliverables"
    ))


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description=f"{ENGINE_NAME}: Modular, Evidence-Grounded Malware Triage & Analysis Platform",
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
    p_analyze.add_argument("--profile", type=str, choices=["minimal", "standard", "full"], default="standard", help="Analysis profile")
    p_analyze.add_argument("--template", "-t", type=str, help="Path to custom DOCX report template")
    p_analyze.add_argument("--privacy", type=str, choices=["strict", "standard", "none"], default="strict", help="Privacy redaction mode")
    p_analyze.add_argument("--offline", action="store_true", help="Force offline deterministic engine (no LLM calls)")
    p_analyze.add_argument("--api-key", type=str, help="OpenAI API key")
    p_analyze.add_argument("--model", type=str, default="gpt-4o", help="LLM model name")

    # Subcommand: doctor
    subparsers.add_parser("doctor", help="Run capability diagnostics and dependency check")

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

    # Backward compatibility: Top-level arguments for direct `0206 --sample ...` or `0206 sample.exe`
    parser.add_argument("direct_target", nargs="?", type=str, help=argparse.SUPPRESS)
    parser.add_argument("--sample", "-s", type=str, help="Target PE binary")
    parser.add_argument("--pcap", "-p", type=str, help="Network capture trace")
    parser.add_argument("--procmon", "-m", type=str, help="Procmon CSV log")
    parser.add_argument("--regshot", "-r", type=str, help="Regshot diff log")
    parser.add_argument("--output", "-o", type=str, help="Output path/directory")
    parser.add_argument("--output-dir", type=str, help="Output path/directory")
    parser.add_argument("--profile", type=str, choices=["minimal", "standard", "full"], default="standard")
    parser.add_argument("--template", "-t", type=str, help="Custom DOCX template")
    parser.add_argument("--privacy", type=str, choices=["strict", "standard", "none"], default="strict")
    parser.add_argument("--offline", action="store_true", help="Force offline mode")
    parser.add_argument("--api-key", type=str, help="OpenAI API key")
    parser.add_argument("--model", type=str, default="gpt-4o")

    args = parser.parse_args()

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
    elif args.subcommand == "analyze":
        sample = args.target or args.sample
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
            model=args.model
        )
        return

    # Direct top-level flags (backward compatibility)
    sample = args.direct_target or args.sample
    if sample or args.pcap or args.procmon:
        out_dir = args.output_dir or args.output
        if out_dir and out_dir.endswith(".docx"):
            out_dir = str(Path(out_dir).parent)
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
            model=args.model
        )
    else:
        cmd_doctor()
        console.print("\n[dim]Run '0206 analyze --help' or '0206 --help' to see analysis options.[/dim]")


if __name__ == "__main__":
    main()
