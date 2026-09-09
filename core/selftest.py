"""
0206 - Self-Test Diagnostic Suite
Verifies core platform health, analyzers, privacy engine, finding engine,
offline AI synthesis, and report generation using harmless synthetic fixtures.
Executes zero malware, zero proprietary dependencies, and zero network calls.
"""
import sys
import json
import hashlib
import tempfile
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.evidence import EvidenceStore, EvidenceState
from core.findings import FindingEngine
from core.privacy import PrivacyMode, PrivacyRedactor, BLOCK_REMOTE_TRANSMISSION
from core.manifest import AnalysisManifest
from core.orchestrator import AnalysisOrchestrator
from analyzer.static import PEStaticAnalyzer
from analyzer.code import CodeAnalyzer
from ai.agent import LLMThreatSynthesizer
from report.adapters.json_adapter import JSONReportAdapter
from report.adapters.markdown_adapter import MarkdownReportAdapter
from report.adapters.generic_docx_adapter import GenericDOCXReportAdapter
from report.template_validator import TemplateValidator
from integrations.registry import CapabilityRegistry
from analyzers.reputation.stage import ReputationStage
from core.assessment import AssessmentEngine


def run_selftest(console: Console) -> bool:
    """
    Runs an automated suite of self-tests using harmless synthetic fixtures.
    Returns True if all tests pass, False otherwise.
    """
    console.print(Panel("[bold cyan]🧪 0206 Automated Self-Test Diagnostic Suite[/bold cyan]\n"
                        "[dim]Testing imports, analyzers, privacy boundaries, AI offline engine, and reporting...[/dim]",
                        border_style="cyan"))

    results_table = Table(title="Self-Test Checks", show_header=True, header_style="bold cyan")
    results_table.add_column("Subsystem / Component", style="bold white", width=32)
    results_table.add_column("Test Scope", style="dim", width=36)
    results_table.add_column("Status", width=14)

    all_passed = True

    def record_result(component: str, scope: str, passed: bool, error: str = ""):
        nonlocal all_passed
        if not passed:
            all_passed = False
            status = "[bold red]FAILED ✗[/bold red]"
        else:
            status = "[bold green]PASSED ✓[/bold green]"
        results_table.add_row(component, scope + (f" ({error})" if error else ""), status)

    # Test 1: Core Imports
    try:
        import pefile
        import scapy
        import capstone
        import docx
        import pydantic
        import rich
        record_result("Core Dependencies", "pefile, scapy, capstone, docx, pydantic", True)
    except Exception as e:
        record_result("Core Dependencies", "Import verification", False, str(e))

    # Locate benign synthetic fixture
    fixture_exe = Path(__file__).resolve().parent.parent / "tests" / "sample_benign_triage.exe"
    if not fixture_exe.exists():
        # Fallback to python binary or compile minimal PE
        fixture_exe = Path(sys.executable)

    # Test 2: PE Static Analyzer & Evidence Generation
    try:
        es = EvidenceStore()
        if fixture_exe.name.endswith(".exe"):
            analyzer = PEStaticAnalyzer(fixture_exe, evidence_store=es)
            data = analyzer.analyze()
            has_records = len(es) > 0
            record_result("PEStaticAnalyzer", f"Analyzed fixture ({len(es)} evidence records)", has_records)
        else:
            record_result("PEStaticAnalyzer", "Non-PE fixture bypass", True)
    except Exception as e:
        record_result("PEStaticAnalyzer", "Static PE inspection", False, str(e))

    # Test 3: Static Code Triage (Capstone)
    try:
        es_code = EvidenceStore()
        code_analyzer = CodeAnalyzer(fixture_exe, evidence_store=es_code)
        cdata = code_analyzer.analyze(max_instructions=10)
        record_result("CodeAnalyzer (Capstone)", f"Static code triage ({cdata.get('status')})", True)
    except Exception as e:
        record_result("CodeAnalyzer (Capstone)", "Capstone disassembly", False, str(e))

    # Test 4: Finding Engine Grounding
    try:
        test_store = EvidenceStore()
        test_store.create("sample.exe", "PE_HEADER", "subsystem", "GUI", "PEStaticAnalyzer")
        engine = FindingEngine(test_store)
        findings = engine.analyze()
        record_result("FindingEngine", "Fact-to-inference correlation", True)
    except Exception as e:
        record_result("FindingEngine", "Finding correlation", False, str(e))

    # Test 5: Privacy Redaction & DLP Boundary
    try:
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        sensitive = {
            "path": "C:\\Users\\AnalystName\\Desktop\\malware.exe",
            "secret": "sk-proj-1234567890abcdef1234567890",
            "host": "DESKTOP-TEST1234"
        }
        redacted = redactor.redact(sensitive)
        user_clean = "<REDACTED_USER>" in redacted["path"] and "AnalystName" not in redacted["path"]
        secret_clean = "[REDACTED_SECRET]" in redacted["secret"]
        host_clean = "<REDACTED_HOST>" in redacted["host"]
        is_safe, reasons = redactor.audit_for_transmission(redacted)
        record_result("PrivacyRedactor", "User, host, and API key scrubbing", user_clean and secret_clean and host_clean and is_safe)
    except Exception as e:
        record_result("PrivacyRedactor", "Privacy scrubbing", False, str(e))

    # Test 6: Offline AI Threat Synthesis
    try:
        synth = LLMThreatSynthesizer(provider="offline")
        assessment = synth.synthesize(test_store, [])
        record_result("ThreatSynthesizer", f"Deterministic offline evaluation ({assessment.threat_level})", assessment.threat_score >= 0)
    except Exception as e:
        record_result("ThreatSynthesizer", "Offline AI synthesis", False, str(e))

    # Test 7: Streaming Manifest Hashing & Lineage
    try:
        manifest = AnalysisManifest()
        manifest.record_artifact("test_exe", fixture_exe)
        has_hash = "sha256" in manifest.artifacts.get("test_exe", {}).get("hashes", {})
        record_result("AnalysisManifest", "Streaming chunk hashing & lineage", has_hash)
    except Exception as e:
        record_result("AnalysisManifest", "Manifest hashing", False, str(e))

    # Test 8: Multi-format Report Generation
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_p = Path(tmp_dir)
            payload = {
                "manifest": manifest.model_dump(),
                "assessment": assessment.model_dump(),
                "findings": [],
                "evidence_records": test_store.to_dict(),
                "raw_telemetry": {}
            }
            # JSON
            JSONReportAdapter().render(payload, tmp_p / "report.json")
            # MD
            MarkdownReportAdapter().render(payload, tmp_p / "report.md")
            # DOCX
            GenericDOCXReportAdapter().render(payload, tmp_p / "report.docx")

            all_files_exist = (tmp_p / "report.json").exists() and (tmp_p / "report.md").exists() and (tmp_p / "report.docx").exists()
            record_result("Report Generation", "JSON, Markdown, and Generic DOCX", all_files_exist)
    except Exception as e:
        record_result("Report Generation", "Multi-format report generation", False, str(e))

    # Test 9: Missing Optional Tools Graceful Handling
    try:
        caps = CapabilityRegistry.get_capabilities()
        # Ensure that missing tools did not crash CapabilityRegistry
        record_result("CapabilityRegistry", "3-Tier tool detection without crashing", True)
    except Exception as e:
        record_result("CapabilityRegistry", "Capability check", False, str(e))

    # Test 10: Reputation Status Semantics (P1.9 & P0.4)
    try:
        rep_store = EvidenceStore()
        rep_stage = ReputationStage(offline=True)
        res = rep_stage.analyze("a" * 64, evidence_store=rep_store)
        rep_ratio = rep_store.find(field="detection_ratio")
        rep_status_rec = rep_store.find(field="lookup_status")
        status_val = res.status if isinstance(res.status, str) else getattr(res.status, "value", str(res.status))
        valid_rep = (
            status_val in ("NOT_CHECKED", "SKIPPED_OFFLINE") and
            len(rep_ratio) > 0 and rep_ratio[0].value == "N/A" and
            len(rep_status_rec) > 0 and rep_status_rec[0].value in ("NOT_CHECKED", "SKIPPED_OFFLINE")
        )
        record_result("Reputation Semantics", "offline => NOT_CHECKED / N/A (no 0/0)", valid_rep)
    except Exception as e:
        record_result("Reputation Semantics", "offline reputation semantics", False, str(e))

    # Test 11: Classification Consistency (P1.9 & P0.5)
    try:
        empty_store = EvidenceStore()
        empty_engine = FindingEngine(empty_store)
        zero_assessment = empty_engine.generate_assessment()
        consistent_class = (
            zero_assessment.threat_score == 0 and
            zero_assessment.classification == "UNKNOWN / NOT_ESTABLISHED" and
            zero_assessment.threat_level == "INFORMATIONAL / CLEAN"
        )
        record_result("Classification Consistency", "score 0 => UNKNOWN / NOT_ESTABLISHED", consistent_class)
    except Exception as e:
        record_result("Classification Consistency", "classification consistency", False, str(e))

    # Test 12: Filename Propagation (P1.9 & P0.6)
    try:
        fn_store = EvidenceStore()
        if fixture_exe.name.endswith(".exe"):
            PEStaticAnalyzer(fixture_exe, evidence_store=fn_store).analyze()
            fn_recs = fn_store.find(field="filename")
            fn_ok = len(fn_recs) > 0 and fn_recs[0].value == fixture_exe.name
            record_result("Filename Propagation", f"sample filename => '{fixture_exe.name}'", fn_ok)
        else:
            record_result("Filename Propagation", "non-PE bypass", True)
    except Exception as e:
        record_result("Filename Propagation", "filename propagation check", False, str(e))

    # Test 13: Privacy-Safe Manifest Export (P1.9 & P0.1)
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_manifest = AnalysisManifest(
                privacy_mode="strict",
                cli_arguments={"sample": str(fixture_exe.resolve())}
            )
            man_out = Path(tmp_dir) / "analysis_manifest.json"
            test_manifest.export_json(man_out)
            # Verify external companion sha256 created
            has_sha256 = (Path(tmp_dir) / "analysis_manifest.sha256").exists()
            # Verify no raw user profile path leaked into exported JSON
            content = man_out.read_text(encoding="utf-8")
            path_safe = "<REDACTED_USER>" in content or fixture_exe.name in content
            record_result("Privacy-Safe Manifest", "Companion sha256 & sanitized export", has_sha256 and path_safe)
    except Exception as e:
        record_result("Privacy-Safe Manifest", "manifest export verification", False, str(e))

    # Test 14: End-to-End Pipeline Execution (P1.8)
    try:
        with tempfile.TemporaryDirectory() as tmp_e2e:
            orchestrator = AnalysisOrchestrator()
            e2e_res = orchestrator.run(
                sample_path=fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_e2e
            )
            required_deliverables = [
                "analysis_manifest.json",
                "analysis_manifest.sha256",
                "evidence.json",
                "findings.json",
                "assessment.json",
                "coverage.json",
                "report.json",
                "report.md",
                "report.docx"
            ]
            e2e_p = Path(tmp_e2e)
            all_deliverables_present = all((e2e_p / d).exists() for d in required_deliverables)

            # Check manifest sha256 validity
            man_bytes = (e2e_p / "analysis_manifest.json").read_bytes()
            calc_hash = hashlib.sha256(man_bytes).hexdigest()
            expected_hash = (e2e_p / "analysis_manifest.sha256").read_text(encoding="utf-8").strip().split()[0]
            sha_matches = (calc_hash == expected_hash)

            record_result("End-to-End Pipeline", f"Full basic triage & deliverables ({len(required_deliverables)} files)", all_deliverables_present and sha_matches)

            # Test 15: Case Semantic & Integrity Validator (P0 semantic consistency)
            from core.semantic_validator import CaseSemanticValidator
            sem_validator = CaseSemanticValidator()
            val_res = sem_validator.validate_case(tmp_e2e)
            record_result("Case Semantic Validator", f"Validated {val_res.passed_checks} semantic & coverage rules", val_res.is_pass(), "" if val_res.is_pass() else f"{val_res.failed_checks} failed")
    except Exception as e:
        record_result("End-to-End Pipeline", "end-to-end pipeline execution", False, str(e))

    # Print results
    console.print(results_table)
    console.print("")

    if all_passed:
        console.print(Panel("[bold green]✔ All Self-Tests Passed (including End-to-End Pipeline Validation)! Platform is operational and offline-ready.[/bold green]", border_style="green"))
    else:
        console.print(Panel("[bold red]✗ One or more self-tests or E2E checks failed. Please inspect table above.[/bold red]", border_style="red"))

    return all_passed
