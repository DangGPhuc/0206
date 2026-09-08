#!/usr/bin/env python3
"""
AutoSleuth-Triage: AI-Assisted Malware Triage & SANS FOR610 Report Engine
CLI Entry Point with Rich Terminal Formatting.
"""
import sys
import json
import argparse
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text

from config import DEFAULT_TEMPLATE_PATH
from analyzer.static import PEStaticAnalyzer
from analyzer.behavioral import BehavioralAnalyzer
from ai.agent import LLMThreatSynthesizer
from reporter.docx_generator import FOR610ReportGenerator

console = Console()


def print_banner():
    """Renders the tool banner."""
    banner_text = Text()
    banner_text.append("⚡ AutoSleuth-Triage ⚡\n", style="bold cyan")
    banner_text.append("AI-Assisted Malware Triage & Automated SANS FOR610 Report Engine\n", style="italic white")
    banner_text.append("Reverse Engineering • Behavioral Telemetry • MITRE ATT&CK • SANS GREM", style="dim green")
    console.print(Panel(banner_text, border_style="cyan", expand=False))


def display_static_summary(static_data: dict):
    """Prints rich formatted table of static analysis results."""
    file_info = static_data.get("file_info", {})
    
    # File Metadata Table
    meta_table = Table(title="🔍 PE File Metadata", show_header=True, header_style="bold magenta")
    meta_table.add_column("Property", style="cyan", width=22)
    meta_table.add_column("Value", style="white")

    meta_table.add_row("File Name", file_info.get("file_name", "N/A"))
    meta_table.add_row("File Size", f"{file_info.get('file_size', 0):,} bytes")
    meta_table.add_row("Architecture", file_info.get("architecture", "N/A"))
    meta_table.add_row("Subsystem", file_info.get("subsystem", "N/A"))
    meta_table.add_row("Compile Time", file_info.get("compile_time", "N/A"))
    meta_table.add_row("SHA256", file_info.get("sha256", "N/A"))
    meta_table.add_row("Imphash", file_info.get("imphash", "N/A"))
    
    entropy = file_info.get("overall_entropy", 0.0)
    entropy_style = "bold red" if entropy >= 7.0 else "green"
    meta_table.add_row("Overall Entropy", f"[{entropy_style}]{entropy:.4f}[/{entropy_style}]")
    meta_table.add_row("Signed", "✅ Yes" if file_info.get("is_signed") else "❌ No (Unsigned)")
    console.print(meta_table)

    # Section Table
    sections = static_data.get("sections", [])
    if sections:
        sec_table = Table(title="📦 PE Sections Analysis", show_header=True, header_style="bold blue")
        sec_table.add_column("Name", style="bold")
        sec_table.add_column("Raw Size")
        sec_table.add_column("Virt Size")
        sec_table.add_column("Entropy")
        sec_table.add_column("Perms")
        sec_table.add_column("Flags")

        for s in sections:
            ent = s.get("entropy", 0.0)
            ent_str = f"[bold red]{ent:.2f}[/bold red]" if ent >= 7.0 else f"{ent:.2f}"
            perms = s.get("permissions", "")
            rwx_flag = "[bold red]⚠️ RWX[/bold red]" if s.get("is_rwx") else perms
            sec_table.add_row(
                s.get("name", ""),
                f"{s.get('raw_size', 0):,}",
                f"{s.get('virtual_size', 0):,}",
                ent_str,
                perms,
                rwx_flag
            )
        console.print(sec_table)

    # API Hashing Matches (Maldev module)
    api_hashes = static_data.get("api_hashing_matches", [])
    if api_hashes:
        hash_table = Table(title="🎯 Detected API Hashing Constants (Obfuscation)", show_header=True, header_style="bold yellow")
        hash_table.add_column("Hash Value", style="yellow")
        hash_table.add_column("Algorithm", style="cyan")
        hash_table.add_column("Resolved Win32 API", style="bold green")
        hash_table.add_column("Binary Offset", style="dim")

        for h in api_hashes[:10]:
            hash_table.add_row(h.get("hash_hex"), h.get("algorithm"), h.get("api"), h.get("offset_hex"))
        console.print(hash_table)

    # Detected Capabilities
    caps = static_data.get("detected_capabilities", {})
    if caps:
        cap_table = Table(title="⚔️ Detected Malware Capabilities (Win32 APIs)", show_header=True, header_style="bold red")
        cap_table.add_column("Capability / Tactic", style="bold red", width=30)
        cap_table.add_column("Matched APIs", style="white")

        for cap, api_list in caps.items():
            cap_table.add_row(cap, ", ".join(api_list))
        console.print(cap_table)


def display_behavioral_summary(behavioral_data: dict):
    """Prints rich formatted table of dynamic/behavioral findings."""
    network = behavioral_data.get("network", {})
    host_beh = behavioral_data.get("host_behavior", {})

    # Network Table
    dns_queries = network.get("dns_queries", [])
    http_reqs = network.get("http_requests", [])
    if dns_queries or http_reqs:
        net_table = Table(title="🌐 Network Artifacts (PCAP Ingestion)", show_header=True, header_style="bold cyan")
        net_table.add_column("Type", style="cyan", width=12)
        net_table.add_column("Details", style="white")

        for d in dns_queries[:6]:
            ips = ", ".join(d.get("resolved_ips", [])) or "Unresolved"
            net_table.add_row("DNS Query", f"{d.get('domain')} -> [{ips}]")
        for h in http_reqs[:6]:
            net_table.add_row("HTTP Request", f"{h.get('method')} http://{h.get('host')}{h.get('uri')} (UA: {h.get('user_agent')})")
        console.print(net_table)

    # Host Behavior Table
    dropped = host_beh.get("dropped_files", [])
    pers = host_beh.get("persistence_registry", [])
    if dropped or pers:
        host_table = Table(title="💻 Host Behavior & Persistence (Procmon Ingestion)", show_header=True, header_style="bold orange1")
        host_table.add_column("Category", style="bold orange1", width=16)
        host_table.add_column("Artifact Path / Key", style="white")

        for df in dropped[:5]:
            host_table.add_row("Dropped File", f"[{df.get('process')}] {df.get('path')}")
        for pr in pers[:5]:
            host_table.add_row("Persistence Key", f"{pr.get('key_path')} (Value: {pr.get('detail')})")
        console.print(host_table)


def display_threat_synthesis(ai_data: dict):
    """Displays threat level badge and MITRE ATT&CK mapping."""
    level = ai_data.get("threat_level", "UNKNOWN")
    score = ai_data.get("threat_score", 0)
    family = ai_data.get("malware_family", "Generic")

    color_map = {
        "CRITICAL": "red",
        "HIGH": "bright_red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFORMATIONAL / CLEAN": "green"
    }
    badge_color = color_map.get(level, "white")

    summary_panel = Panel(
        f"[{badge_color}]Threat Assessment: {level} (Score: {score}/100)[/{badge_color}]\n"
        f"[bold white]Classification:[/bold white] {family}\n\n"
        f"[italic]{ai_data.get('executive_summary', '')}[/italic]",
        title="🧠 AI Threat Synthesizer Summary",
        border_style=badge_color
    )
    console.print(summary_panel)

    # MITRE ATT&CK Table
    mitre_list = ai_data.get("mitre_attack", [])
    if mitre_list:
        mitre_table = Table(title="🛡️ MITRE ATT&CK Mapping", show_header=True, header_style="bold green")
        mitre_table.add_column("Technique ID", style="bold green", width=15)
        mitre_table.add_column("Technique Name", style="white", width=25)
        mitre_table.add_column("Tactic", style="cyan", width=22)
        mitre_table.add_column("Observed Evidence", style="dim")

        for m in mitre_list:
            mitre_table.add_row(
                m.get("technique_id", ""),
                m.get("technique_name", ""),
                m.get("tactic", ""),
                m.get("evidence", "")
            )
        console.print(mitre_table)


def main():
    parser = argparse.ArgumentParser(
        description="AutoSleuth-Triage: AI-Assisted Malware Triage & SANS FOR610 Report Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("--sample", "-s", type=str, help="Path to suspicious Windows PE file (.exe, .dll, .sys)")
    parser.add_argument("--pcap", "-p", type=str, help="Path to network capture trace (.pcap)")
    parser.add_argument("--procmon", "-m", type=str, help="Path to Process Monitor log (.csv)")
    parser.add_argument("--regshot", "-r", type=str, help="Path to Regshot diff log (.txt)")
    parser.add_argument("--output", "-o", type=str, help="Output destination for SANS FOR610 DOCX report")
    parser.add_argument("--json-output", "-j", type=str, help="Optional destination to export full raw JSON telemetry")
    parser.add_argument("--template", "-t", type=str, help="Custom SANS FOR610 DOCX template path")
    parser.add_argument("--llm-provider", type=str, choices=["auto", "openai", "ollama", "heuristic"], default="auto", help="LLM synthesis provider")
    parser.add_argument("--api-key", type=str, help="OpenAI API key (or set OPENAI_API_KEY env var)")
    parser.add_argument("--api-base", type=str, help="Custom OpenAI-compatible API base URL (e.g. http://localhost:11434/v1)")
    parser.add_argument("--model", type=str, default="gpt-4o", help="LLM model identifier")

    args = parser.parse_args()
    print_banner()

    if not args.sample and not args.pcap and not args.procmon:
        console.print("[bold red][!] Error:[/bold red] At least one input artifact (--sample, --pcap, or --procmon) must be provided.")
        parser.print_help()
        sys.exit(1)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress:

        # Step 1: Static Analysis
        static_task = progress.add_task("[cyan]Executing Static PE Analysis...", total=100)
        static_data = {}
        if args.sample:
            sample_path = Path(args.sample)
            if sample_path.exists():
                analyzer = PEStaticAnalyzer(sample_path)
                static_data = analyzer.analyze()
            else:
                console.print(f"[bold red][!] Warning:[/bold red] Sample file not found: {args.sample}")
        progress.update(static_task, completed=100)

        # Step 2: Behavioral Ingestion
        beh_task = progress.add_task("[yellow]Ingesting Behavioral Artifacts (PCAP/Procmon)...", total=100)
        beh_analyzer = BehavioralAnalyzer(
            pcap_path=args.pcap,
            procmon_path=args.procmon,
            regshot_path=args.regshot
        )
        behavioral_data = beh_analyzer.analyze()
        progress.update(beh_task, completed=100)

        # Step 3: AI Threat Synthesizer
        ai_task = progress.add_task("[magenta]Synthesizing Threat Intel & MITRE ATT&CK (AI Engine)...", total=100)
        full_telemetry = {
            "static": static_data,
            "behavioral": behavioral_data
        }
        synthesizer = LLMThreatSynthesizer(
            provider=args.llm_provider,
            api_key=args.api_key,
            api_base=args.api_base,
            model=args.model
        )
        ai_data = synthesizer.synthesize(full_telemetry)
        progress.update(ai_task, completed=100)

        # Step 4: DOCX Report Generation
        report_task = progress.add_task("[green]Compiling SANS FOR610 DOCX Report...", total=100)
        
        # Determine output report name
        if args.output:
            output_docx = Path(args.output)
        elif args.sample:
            sample_name = Path(args.sample).stem
            output_docx = Path(f"Malware_Analysis_Report_{sample_name}.docx")
        else:
            output_docx = Path("Malware_Analysis_Report_Behavioral.docx")

        template_path = Path(args.template) if args.template else DEFAULT_TEMPLATE_PATH
        reporter = FOR610ReportGenerator(template_path=template_path)
        final_report_path = reporter.generate(
            static_data=static_data,
            behavioral_data=behavioral_data,
            ai_data=ai_data,
            output_path=output_docx
        )
        progress.update(report_task, completed=100)

    # Display Rich Summaries on Console
    console.print("\n")
    if static_data:
        display_static_summary(static_data)
        console.print("\n")

    if behavioral_data.get("network", {}).get("dns_queries") or behavioral_data.get("host_behavior", {}).get("dropped_files"):
        display_behavioral_summary(behavioral_data)
        console.print("\n")

    display_threat_synthesis(ai_data)
    console.print("\n")

    # Export raw JSON if requested
    if args.json_output:
        json_path = Path(args.json_output)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        export_payload = {
            "static": static_data,
            "behavioral": behavioral_data,
            "ai_synthesis": ai_data
        }
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(export_payload, jf, indent=2)
        console.print(f"📄 [dim]Raw JSON telemetry exported to:[/dim] [cyan]{json_path.resolve()}[/cyan]")

    # Final Success Message
    console.print(Panel(
        f"[bold green]✔ Triage & Analysis Complete![/bold green]\n\n"
        f"Generated Report: [bold white]{final_report_path.resolve()}[/bold white]\n"
        f"Template Used:    [dim]{template_path}[/dim]\n"
        f"Format:           [cyan]SANS FOR610 DOCX Standard[/cyan]",
        border_style="green",
        title="🎉 SANS FOR610 Report Ready"
    ))


if __name__ == "__main__":
    main()
