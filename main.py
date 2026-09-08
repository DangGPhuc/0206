#!/usr/bin/env python3
"""
0206: Modular, Evidence-Grounded Malware Triage & Analysis Platform
CLI Entry Point with Rich Terminal UI, Doctor Health Check, and Multi-format Reporting.
"""
import sys
import os
import json
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text

from config import (
    ENGINE_NAME, ENGINE_VERSION,
    MAX_SAMPLE_SIZE, MAX_PCAP_SIZE
)
from core.paths import get_template_path, get_output_dir
from core.evidence import EvidenceStore
from core.findings import FindingEngine
from core.manifest import AnalysisManifest
from core.privacy import PrivacyMode, PrivacyRedactor
from core.validators import validate_file_size, validate_finding_evidence_grounding

from analyzer.static import PEStaticAnalyzer
from analyzer.behavioral import BehavioralAnalyzer
from analyzer.code import CodeAnalyzer
from ai.agent import LLMThreatSynthesizer
from integrations.registry import CapabilityRegistry

from report.adapters.json_adapter import JSONReportAdapter
from report.adapters.markdown_adapter import MarkdownReportAdapter
from report.adapters.generic_docx_adapter import GenericDOCXReportAdapter
from report.adapters.sans_style_adapter import SANSStyleReportAdapter
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
    """Runs the environment and tool capability health check."""
    caps = CapabilityRegistry.get_capabilities()
    
    doc_table = Table(title="🔍 0206 Environment & Capability Doctor", show_header=True, header_style="bold cyan")
    doc_table.add_column("Component / Tool", style="bold white", width=22)
    doc_table.add_column("Tier", style="dim", width=20)
    doc_table.add_column("Status", width=16)
    doc_table.add_column("Version / Details", style="italic")

    all_tier1_ok = True

    for name, info in caps.items():
        status = info["status"]
        tier = info["tier"]
        version = info.get("version") or info.get("path") or ""

        if status == "AVAILABLE":
            status_style = "[bold green]AVAILABLE  ✓[/bold green]"
        elif status == "NOT_INSTALLED":
            status_style = "[yellow]NOT INSTALLED -[/yellow]"
        elif status == "NOT_AVAILABLE_ON_PLATFORM":
            status_style = "[dim]N/A ON OS     -[/dim]"
        else:
            status_style = "[bold red]MISSING     ✗[/bold red]"
            if "Tier 1" in tier:
                all_tier1_ok = False

        doc_table.add_row(name, tier, status_style, version)

    console.print(doc_table)

    # Operational status summary
    status_text = "[bold green]Status: READY FOR ANALYSIS[/bold green]" if all_tier1_ok else "[bold red]Status: DEGRADED (Install missing Tier 1 dependencies)[/bold red]"
    summary_panel = Panel(
        f"Python: {sys.version.split()[0]} | Platform: {sys.platform}\n"
        f"Evidence Engine: Canonical 3-Tier (Evidence -> Finding -> Assessment)\n"
        f"Privacy Mode: strict (default) | Default Pipeline: Offline-safe\n\n"
        f"{status_text}",
        title="🏥 Doctor Diagnosis Summary",
        border_style="green" if all_tier1_ok else "red"
    )
    console.print(summary_panel)


def cmd_capabilities():
    """Displays detailed capability matrix."""
    cmd_doctor()


def cmd_validate_template(template_path: str):
    """Validates a user-provided DOCX template."""
    p = Path(template_path)
    console.print(f"[*] Validating template structure: [cyan]{p.resolve()}[/cyan] ...")
    valid, warnings = TemplateValidator.validate_sans_style_template(p)
    if valid:
        console.print(f"[bold green]✔ Template is valid and compatible with SANS-style report adapter.[/bold green]")
        if warnings:
            for w in warnings:
                console.print(f"  [yellow]Warning:[/yellow] {w}")
    else:
        console.print(f"[bold red]✗ Template validation failed:[/bold red]")
        for w in warnings:
            console.print(f"  • {w}")


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


def run_pipeline(
    sample_path: Optional[str] = None,
    pcap_path: Optional[str] = None,
    procmon_path: Optional[str] = None,
    regshot_path: Optional[str] = None,
    output_dir_str: Optional[str] = None,
    template_path_str: Optional[str] = None,
    privacy_mode_str: str = "strict",
    offline_mode: bool = False,
    api_key: Optional[str] = None,
    model: str = "gpt-4o"
):
    """Executes the full modular triage pipeline."""
    if not sample_path and not pcap_path and not procmon_path:
        console.print("[bold red][!] Error:[/bold red] At least one input artifact (--sample, --pcap, or --procmon) is required.")
        sys.exit(1)

    # Initialize Evidence Store & Manifest
    evidence_store = EvidenceStore()
    manifest = AnalysisManifest(privacy_mode=privacy_mode_str)
    privacy_redactor = PrivacyRedactor(mode=privacy_mode_str)

    output_dir = Path(output_dir_str) if output_dir_str else get_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    static_data = {}
    behavioral_data = {}
    code_data = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress:

        # Step 1: Static PE Inspection
        if sample_path:
            p_sample = Path(sample_path)
            manifest.record_artifact("sample", p_sample)
            manifest.sample_filename = p_sample.name
            manifest.sample_size_bytes = p_sample.stat().st_size if p_sample.exists() else 0

            s_task = progress.add_task("[cyan]Module 1: Static PE Analysis & Section Entropy...", total=100)
            static_analyzer = PEStaticAnalyzer(p_sample, evidence_store=evidence_store)
            static_data = static_analyzer.analyze()
            manifest.analyzers_enabled.append("PEStaticAnalyzer")
            progress.update(s_task, completed=100)

            # Step 2: Code Disassembly (Capstone)
            c_task = progress.add_task("[blue]Module 2: Static Entry-Point Disassembly (Capstone)...", total=100)
            code_analyzer = CodeAnalyzer(p_sample, evidence_store=evidence_store)
            code_data = code_analyzer.analyze()
            manifest.analyzers_enabled.append("CodeAnalyzer")
            progress.update(c_task, completed=100)
        else:
            manifest.analyzers_skipped.append("PEStaticAnalyzer")
            manifest.analyzers_skipped.append("CodeAnalyzer")

        # Step 3: Behavioral Artifact Ingestion
        if pcap_path or procmon_path or regshot_path:
            b_task = progress.add_task("[yellow]Module 3: Ingesting Behavioral Artifacts (PCAP & Procmon)...", total=100)
            if pcap_path: manifest.record_artifact("pcap", Path(pcap_path))
            if procmon_path: manifest.record_artifact("procmon", Path(procmon_path))
            if regshot_path: manifest.record_artifact("regshot", Path(regshot_path))

            beh_analyzer = BehavioralAnalyzer(
                pcap_path=pcap_path,
                procmon_path=procmon_path,
                regshot_path=regshot_path,
                evidence_store=evidence_store
            )
            behavioral_data = beh_analyzer.analyze()
            manifest.analyzers_enabled.append("BehavioralAnalyzer")
            progress.update(b_task, completed=100)
        else:
            manifest.analyzers_skipped.append("BehavioralAnalyzer")

        # Step 4: Finding Engine Correlation
        f_task = progress.add_task("[magenta]Module 4: Finding Engine Correlation (Facts -> Inferences)...", total=100)
        finding_engine = FindingEngine(evidence_store)
        raw_findings = finding_engine.analyze()
        validated_findings, warnings = validate_finding_evidence_grounding(raw_findings, evidence_store)
        manifest.warnings.extend(warnings)
        progress.update(f_task, completed=100)

        # Step 5: Threat Synthesis (AI or Offline Heuristic)
        ai_task = progress.add_task("[bold magenta]Module 5: Threat Synthesis & MITRE ATT&CK Mapping...", total=100)
        llm_provider = "offline" if offline_mode else "auto"
        manifest.ai_mode = llm_provider

        synthesizer = LLMThreatSynthesizer(
            provider=llm_provider,
            api_key=api_key,
            model=model,
            privacy_mode=privacy_mode_str
        )
        assessment = synthesizer.synthesize(evidence_store, validated_findings)
        progress.update(ai_task, completed=100)

        # Step 6: Multi-format Report Generation
        r_task = progress.add_task("[green]Module 6: Compiling Evidence-Grounded Reports (JSON, MD, DOCX)...", total=100)
        manifest.complete()

        # Build Session Report payload
        session_payload = {
            "manifest": manifest.model_dump(),
            "assessment": assessment.model_dump(),
            "findings": [f.model_dump() for f in validated_findings],
            "evidence_records": evidence_store.to_dict(),
            "raw_telemetry": {
                "static": static_data,
                "code_analysis": code_data,
                "behavioral": behavioral_data
            }
        }

        # Apply privacy redactor to exported session payload
        sanitized_payload = privacy_redactor.redact(session_payload)

        # 1. Export JSON Report
        json_adapter = JSONReportAdapter()
        report_json_path = output_dir / "report.json"
        json_adapter.render(sanitized_payload, report_json_path)

        # 2. Export Markdown Report
        md_adapter = MarkdownReportAdapter()
        report_md_path = output_dir / "report.md"
        md_adapter.render(sanitized_payload, report_md_path)

        # 3. Export DOCX Report
        report_docx_path = output_dir / "report.docx"
        if template_path_str and Path(template_path_str).exists():
            # Use user template with SANS adapter if valid
            try:
                docx_adapter = SANSStyleReportAdapter(Path(template_path_str))
                manifest.template_name = Path(template_path_str).name
            except Exception:
                docx_adapter = GenericDOCXReportAdapter()
                manifest.template_name = "generic_builtin"
        else:
            # Clean generic built-in DOCX report
            docx_adapter = GenericDOCXReportAdapter()
            manifest.template_name = "generic_builtin"

        docx_adapter.render(sanitized_payload, report_docx_path)

        # Export standalone manifest and evidence files
        manifest.export_json(output_dir / "analysis_manifest.json")
        with open(output_dir / "evidence.json", "w", encoding="utf-8") as ef:
            json.dump(evidence_store.to_dict(), ef, indent=2)

        progress.update(r_task, completed=100)

    # ---------------- UI Presentation ----------------
    console.print("\n")
    display_findings_table(validated_findings)
    console.print("\n")

    # Threat Assessment Panel
    level = assessment.threat_level
    badge_colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow", "LOW": "blue"}
    color = badge_colors.get(level, "green")
    
    panel_content = (
        f"[{color}]Assessment: {level} (Score: {assessment.threat_score}/100)[/{color}]\n"
        f"[bold white]Classification:[/bold white] {assessment.classification}\n\n"
        f"[italic]{assessment.summary}[/italic]\n\n"
        f"[bold cyan]Grounding:[/bold cyan] Grounded in {len(evidence_store)} verified EvidenceRecords and {len(validated_findings)} Findings."
    )
    console.print(Panel(panel_content, title="🛡️ 0206 Triage Assessment", border_style=color))

    # Deliverables Summary Panel
    console.print(Panel(
        f"[bold green]✔ Analysis Complete & Deliverables Exported![/bold green]\n\n"
        f"  📁 Output Directory: [cyan]{output_dir.resolve()}[/cyan]\n"
        f"  📄 Machine JSON:     [white]{report_json_path.name}[/white]\n"
        f"  📝 Markdown Report:  [white]{report_md_path.name}[/white]\n"
        f"  📘 Word Document:    [white]{report_docx_path.name}[/white]\n"
        f"  📑 Audit Manifest:   [white]analysis_manifest.json[/white]\n"
        f"  🔍 Evidence Store:   [white]evidence.json[/white]",
        border_style="green",
        title="📦 Session Deliverables"
    ))


def main():
    print_banner()

    # Top-level parser supporting both subcommands and backward-compatible direct flags
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
    p_analyze.add_argument("--template", "-t", type=str, help="Path to custom DOCX report template")
    p_analyze.add_argument("--privacy", type=str, choices=["strict", "standard", "none"], default="strict", help="Privacy redaction mode")
    p_analyze.add_argument("--offline", action="store_true", help="Force offline deterministic engine (no LLM calls)")
    p_analyze.add_argument("--api-key", type=str, help="OpenAI API key")
    p_analyze.add_argument("--model", type=str, default="gpt-4o", help="LLM model name")

    # Subcommand: doctor
    subparsers.add_parser("doctor", help="Run capability diagnostics and dependency check")

    # Subcommand: capabilities
    subparsers.add_parser("capabilities", help="List detected Tier 1, 2, and 3 capabilities")

    # Subcommand: validate-template
    p_val = subparsers.add_parser("validate-template", help="Validate a DOCX report template")
    p_val.add_argument("template_path", type=str, help="Path to DOCX template file")

    # Backward compatibility: Top-level arguments for direct `python main.py --sample ...`
    parser.add_argument("--sample", "-s", type=str, help="Target PE binary")
    parser.add_argument("--pcap", "-p", type=str, help="Network capture trace")
    parser.add_argument("--procmon", "-m", type=str, help="Procmon CSV log")
    parser.add_argument("--regshot", "-r", type=str, help="Regshot diff log")
    parser.add_argument("--output", "-o", type=str, help="Output path/directory")
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
    elif args.subcommand == "validate-template":
        cmd_validate_template(args.template_path)
        return
    elif args.subcommand == "analyze":
        sample = args.target or args.sample
        run_pipeline(
            sample_path=sample,
            pcap_path=args.pcap,
            procmon_path=args.procmon,
            regshot_path=args.regshot,
            output_dir_str=args.output_dir,
            template_path_str=args.template,
            privacy_mode_str=args.privacy,
            offline_mode=args.offline,
            api_key=args.api_key,
            model=args.model
        )
        return

    # Direct top-level flags (backward compatibility)
    if args.sample or args.pcap or args.procmon:
        out_dir = args.output
        if out_dir and out_dir.endswith(".docx"):
            out_dir = str(Path(out_dir).parent)
        run_pipeline(
            sample_path=args.sample,
            pcap_path=args.pcap,
            procmon_path=args.procmon,
            regshot_path=args.regshot,
            output_dir_str=out_dir,
            template_path_str=args.template,
            privacy_mode_str=args.privacy,
            offline_mode=args.offline,
            api_key=args.api_key,
            model=args.model
        )
    else:
        # If no arguments provided, show doctor and help
        cmd_doctor()
        console.print("\n[dim]Run 'python3 main.py analyze --help' to see analysis options.[/dim]")


if __name__ == "__main__":
    main()
