"""
0206 - Core Analysis Orchestrator
Realizes the canonical runtime dataflow:
  Input -> Analyzer -> EvidenceStore -> FindingEngine -> PrivacyRedactor -> AI -> Assessment -> Report

Responsibilities:
- Input validation and resource safety limits (ResourcePolicy)
- AnalysisManifest creation and streaming input artifact hashing
- EvidenceStore instantiation
- Static PE and Capstone code triage analysis
- Behavioral artifact analysis (PCAP streaming, Procmon, Regshot)
- Optional Tier 2 and Tier 3 tool adapters
- FindingEngine correlation (grounded inferences derived from facts)
- Finding validation (ensuring every finding maps to valid evidence IDs)
- Mandatory Privacy & DLP filter boundary before remote LLM transmission
- Grounded threat synthesis (AI or deterministic offline heuristic)
- Multi-format report generation (JSON, Markdown, DOCX)
- Output lineage hashing and manifest finalization
"""
import os
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable

from config import (
    ENGINE_NAME, ENGINE_VERSION,
    MAX_SAMPLE_SIZE, MAX_PCAP_SIZE
)
from core.paths import get_template_path, get_output_dir
from core.resource_policy import ResourcePolicy
from core.profiles import ProfileName, get_profile
from core.evidence import EvidenceStore
from core.findings import FindingEngine, Finding, Assessment
from core.manifest import AnalysisManifest
from core.privacy import PrivacyMode, PrivacyRedactor, BLOCK_REMOTE_TRANSMISSION
from core.validators import validate_finding_evidence_grounding

from analyzer.static import PEStaticAnalyzer
from analyzer.behavioral import BehavioralAnalyzer
from analyzer.code import CodeAnalyzer
from ai.agent import LLMThreatSynthesizer
from integrations.adapters import ADAPTER_REGISTRY

from report.adapters.json_adapter import JSONReportAdapter
from report.adapters.markdown_adapter import MarkdownReportAdapter
from report.adapters.generic_docx_adapter import GenericDOCXReportAdapter
from report.adapters.sans_style_adapter import SANSStyleReportAdapter
from report.template_validator import TemplateValidator


@dataclass
class OrchestrationResult:
    """Encapsulates the results and output artifact paths of an analysis session."""
    case_id: str
    output_dir: Path
    manifest: AnalysisManifest
    evidence_store: EvidenceStore
    findings: List[Finding]
    assessment: Assessment
    report_json: Path
    report_md: Path
    report_docx: Path
    evidence_json: Path
    findings_json: Path
    manifest_json: Path
    warnings: List[str] = field(default_factory=list)


class AnalysisOrchestrator:
    """
    Coordinates and drives the entire 0206 malware triage and report generation lifecycle.
    """

    def __init__(self, resource_policy: Optional[ResourcePolicy] = None):
        self.resource_policy = resource_policy or ResourcePolicy()

    def run(
        self,
        sample_path: Optional[str | Path] = None,
        pcap_path: Optional[str | Path] = None,
        procmon_path: Optional[str | Path] = None,
        regshot_path: Optional[str | Path] = None,
        output_dir: Optional[str | Path] = None,
        profile: str = "standard",
        privacy_mode: str = "strict",
        offline: bool = False,
        api_key: Optional[str] = None,
        model: str = "gpt-4o",
        template_path: Optional[str | Path] = None,
        step_callback: Optional[Callable[[str, int], None]] = None
    ) -> OrchestrationResult:
        """
        Executes the end-to-end analysis pipeline.
        """
        def notify(message: str, step: int):
            if step_callback:
                step_callback(message, step)

        # -------------------------------------------------------------
        # 1. Input Validation & Resource Safety
        # -------------------------------------------------------------
        notify("Validating input artifacts and resource policies...", 1)
        p_sample = Path(sample_path) if sample_path else None
        p_pcap = Path(pcap_path) if pcap_path else None
        p_procmon = Path(procmon_path) if procmon_path else None
        p_regshot = Path(regshot_path) if regshot_path else None

        if not p_sample and not p_pcap and not p_procmon and not p_regshot:
            raise ValueError("At least one input artifact (--sample, --pcap, or --procmon) is required.")

        warnings: List[str] = []

        if p_sample:
            ok, err = self.resource_policy.check_sample(p_sample)
            if not ok:
                raise ValueError(err)
        if p_pcap:
            ok, err = self.resource_policy.check_pcap(p_pcap)
            if not ok:
                warnings.append(err or "PCAP resource limit exceeded")
        if p_procmon:
            ok, err = self.resource_policy.check_procmon(p_procmon)
            if not ok:
                warnings.append(err or "Procmon resource limit exceeded")

        # Destination Directory
        out_dir = Path(output_dir) if output_dir else get_output_dir()
        out_dir.mkdir(parents=True, exist_ok=True)

        # -------------------------------------------------------------
        # 2. Manifest & Evidence Store Initialization
        # -------------------------------------------------------------
        notify("Initializing Evidence Store and Analysis Manifest...", 2)
        prof_cfg = get_profile(profile)
        manifest = AnalysisManifest(
            privacy_mode=privacy_mode,
            profile=prof_cfg.name.value,
            cli_arguments={
                "sample": str(p_sample) if p_sample else None,
                "pcap": str(p_pcap) if p_pcap else None,
                "procmon": str(p_procmon) if p_procmon else None,
                "regshot": str(p_regshot) if p_regshot else None,
                "profile": profile,
                "privacy": privacy_mode,
                "offline": offline
            }
        )
        manifest.warnings.extend(warnings)

        evidence_store = EvidenceStore()
        privacy_redactor = PrivacyRedactor(mode=privacy_mode)

        # Record input artifacts streaming hashes into manifest
        if p_sample and p_sample.exists():
            manifest.record_artifact("sample", p_sample)
            manifest.sample_filename = p_sample.name
            manifest.sample_size_bytes = p_sample.stat().st_size
            manifest.sample_hashes = manifest.artifacts.get("sample", {}).get("hashes", {})
        if p_pcap and p_pcap.exists():
            manifest.record_artifact("pcap", p_pcap)
        if p_procmon and p_procmon.exists():
            manifest.record_artifact("procmon", p_procmon)
        if p_regshot and p_regshot.exists():
            manifest.record_artifact("regshot", p_regshot)

        # -------------------------------------------------------------
        # 3. Static Analyzers & Capstone Code Triage
        # -------------------------------------------------------------
        static_data: Dict[str, Any] = {}
        code_data: Dict[str, Any] = {}

        if p_sample and prof_cfg.enable_static:
            notify("Executing static PE analysis and section entropy triage...", 3)
            static_analyzer = PEStaticAnalyzer(p_sample, evidence_store=evidence_store)
            static_data = static_analyzer.analyze()
            manifest.analyzers_enabled.append("PEStaticAnalyzer")

            if prof_cfg.enable_code:
                notify("Executing static code triage (Capstone entry-point disassembly)...", 4)
                code_analyzer = CodeAnalyzer(p_sample, evidence_store=evidence_store)
                code_data = code_analyzer.analyze()
                manifest.analyzers_enabled.append("CodeAnalyzer")
            else:
                manifest.analyzers_skipped.append("CodeAnalyzer")
        else:
            manifest.analyzers_skipped.extend(["PEStaticAnalyzer", "CodeAnalyzer"])

        # -------------------------------------------------------------
        # 4. Behavioral Analyzers (PCAP, Procmon, Regshot)
        # -------------------------------------------------------------
        behavioral_data: Dict[str, Any] = {}
        if prof_cfg.enable_behavioral and (p_pcap or p_procmon or p_regshot):
            notify("Ingesting behavioral telemetry (PCAP streaming & Procmon logs)...", 5)
            beh_analyzer = BehavioralAnalyzer(
                pcap_path=str(p_pcap) if p_pcap else None,
                procmon_path=str(p_procmon) if p_procmon else None,
                regshot_path=str(p_regshot) if p_regshot else None,
                evidence_store=evidence_store
            )
            behavioral_data = beh_analyzer.analyze()
            manifest.analyzers_enabled.append("BehavioralAnalyzer")
        else:
            manifest.analyzers_skipped.append("BehavioralAnalyzer")

        # -------------------------------------------------------------
        # 5. Optional Integrations (Tier 2 & Tier 3 Adapters)
        # -------------------------------------------------------------
        if p_sample:
            for tool_name in prof_cfg.allowed_integrations:
                adapter_cls = ADAPTER_REGISTRY.get(tool_name)
                if adapter_cls:
                    adapter = adapter_cls()
                    if adapter.available():
                        notify(f"Running optional adapter: {tool_name}...", 6)
                        try:
                            adapter.analyze(p_sample, evidence_store=evidence_store)
                            manifest.analyzers_enabled.append(tool_name)
                            manifest.adapter_versions[tool_name] = adapter.version
                        except Exception as ex:
                            manifest.warnings.append(f"Adapter {tool_name} failed: {ex}")
                    else:
                        manifest.analyzers_skipped.append(tool_name)

        # -------------------------------------------------------------
        # 6. Finding Engine Correlation & Evidence Grounding
        # -------------------------------------------------------------
        notify("Correlating evidence facts into calibrated findings...", 7)
        finding_engine = FindingEngine(evidence_store)
        raw_findings = finding_engine.analyze()
        validated_findings, finding_warnings = validate_finding_evidence_grounding(raw_findings, evidence_store)
        manifest.warnings.extend(finding_warnings)

        # -------------------------------------------------------------
        # 7. Privacy Redaction & DLP Boundary before AI
        # -------------------------------------------------------------
        notify("Enforcing privacy/DLP security boundary...", 8)
        llm_provider = "offline" if (offline or prof_cfg.force_offline_ai) else "auto"
        
        # If remote AI is requested, perform DLP audit first
        if llm_provider != "offline" and api_key:
            evidence_summary = evidence_store.to_dict()
            sanitized_evidence = privacy_redactor.redact(evidence_summary)
            is_safe, reasons = privacy_redactor.audit_for_transmission(sanitized_evidence)
            if not is_safe:
                # MANDATORY SECURITY BOUNDARY: Block remote transmission
                manifest.warnings.append(f"{BLOCK_REMOTE_TRANSMISSION}: Sensitive telemetry detected. Fallback to offline AI.")
                llm_provider = "offline"

        manifest.ai_mode = llm_provider

        # -------------------------------------------------------------
        # 8. Threat Synthesis & Assessment
        # -------------------------------------------------------------
        notify("Synthesizing threat assessment...", 9)
        synthesizer = LLMThreatSynthesizer(
            provider=llm_provider,
            api_key=api_key,
            model=model,
            privacy_mode=privacy_mode
        )
        assessment = synthesizer.synthesize(evidence_store, validated_findings)

        # -------------------------------------------------------------
        # 9. Multi-format Deliverable Generation
        # -------------------------------------------------------------
        notify("Compiling deliverables (JSON, Markdown, DOCX, Evidence, Findings)...", 10)
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
        sanitized_payload = privacy_redactor.redact(session_payload)

        # 1. JSON Report
        report_json_path = out_dir / "report.json"
        JSONReportAdapter().render(sanitized_payload, report_json_path)

        # 2. Markdown Report
        report_md_path = out_dir / "report.md"
        MarkdownReportAdapter().render(sanitized_payload, report_md_path)

        # 3. DOCX Report (Generic built-in or user-provided template adapter)
        report_docx_path = out_dir / "report.docx"
        p_template = Path(template_path) if template_path else None
        if p_template and p_template.exists():
            valid, t_warns = TemplateValidator.validate_sans_style_template(p_template)
            if valid:
                docx_adapter = SANSStyleReportAdapter(p_template)
                manifest.template_name = p_template.name
            else:
                docx_adapter = GenericDOCXReportAdapter()
                manifest.template_name = "generic_builtin"
                manifest.warnings.append(f"Custom template invalid, used generic adapter. Reason: {t_warns}")
        else:
            docx_adapter = GenericDOCXReportAdapter()
            manifest.template_name = "generic_builtin"

        docx_adapter.render(sanitized_payload, report_docx_path)

        # 4. Evidence Store JSON export
        evidence_json_path = out_dir / "evidence.json"
        evidence_store.export(evidence_json_path)

        # 5. Findings JSON export
        findings_json_path = out_dir / "findings.json"
        finding_engine.export(findings_json_path)

        # -------------------------------------------------------------
        # 10. Finalize Manifest & Lineage Hashing
        # -------------------------------------------------------------
        notify("Finalizing audit manifest and output lineage hashes...", 11)
        manifest_json_path = out_dir / "analysis_manifest.json"
        
        # Record output artifact lineage
        manifest.record_output_artifact("report.json", report_json_path)
        manifest.record_output_artifact("report.md", report_md_path)
        manifest.record_output_artifact("report.docx", report_docx_path)
        manifest.record_output_artifact("evidence.json", evidence_json_path)
        manifest.record_output_artifact("findings.json", findings_json_path)

        manifest.complete()
        manifest.export_json(manifest_json_path)

        # Record manifest itself into final output
        manifest.record_output_artifact("analysis_manifest.json", manifest_json_path)
        manifest.export_json(manifest_json_path)

        notify("Triage pipeline complete!", 12)

        return OrchestrationResult(
            case_id=manifest.case_id,
            output_dir=out_dir,
            manifest=manifest,
            evidence_store=evidence_store,
            findings=validated_findings,
            assessment=assessment,
            report_json=report_json_path,
            report_md=report_md_path,
            report_docx=report_docx_path,
            evidence_json=evidence_json_path,
            findings_json=findings_json_path,
            manifest_json=manifest_json_path,
            warnings=manifest.warnings
        )
