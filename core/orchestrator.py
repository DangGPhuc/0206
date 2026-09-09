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
import time
import json
import hashlib
from datetime import datetime, timezone
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
from core.privacy import PrivacyMode, PrivacyRedactor, BLOCK_REMOTE_TRANSMISSION, DLPStatus
from core.validators import validate_finding_evidence_grounding
from integrations.registry import CapabilityRegistry

from analyzers.reputation.stage import ReputationStage
from analyzers.static.pe_analyzer import PEStaticAnalyzer
from analyzers.behavioral.event_normalizer import BehavioralAnalyzer
from analyzers.code.capstone_triage import CodeAnalyzer
from ai.agent import LLMThreatSynthesizer
from integrations.adapters import ADAPTER_REGISTRY

from reporting.adapters.json_adapter import JSONReportAdapter
from reporting.adapters.markdown_adapter import MarkdownReportAdapter
from reporting.adapters.generic_docx_adapter import GenericDOCXReportAdapter
from reporting.adapters.sans_style_adapter import SANSStyleReportAdapter
from reporting.validators.template_validator import TemplateValidator


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
    manifest_sha256: Path
    assessment_json: Optional[Path] = None
    iocs_json: Optional[Path] = None
    coverage_json: Optional[Path] = None
    evidence_raw_json: Optional[Path] = None
    warnings: List[str] = field(default_factory=list)


class AnalysisOrchestrator:
    """
    Coordinates and drives the entire 0206 malware triage and report generation lifecycle.
    Guarantees the strict 12-stage pipeline:
      INPUT -> RESOURCE POLICY -> MANIFEST -> ANALYZERS -> EVIDENCE STORE ->
      FINDING ENGINE -> VALIDATION -> DETERMINISTIC ASSESSMENT -> PRIVACY/DLP ->
      OPTIONAL AI ENRICHMENT -> AI VALIDATION -> REPORT -> OUTPUT LINEAGE
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
        yara_rules: Optional[str | Path] = None,
        backend: str = "memory",
        adaptive: bool = False,
        portable: bool = False,
        export_raw_evidence: bool = False,
        step_callback: Optional[Callable[[str, int], None]] = None
    ) -> OrchestrationResult:
        """
        Executes the end-to-end analysis pipeline.
        """
        def notify(message: str, step: int):
            if step_callback:
                step_callback(message, step)

        # -------------------------------------------------------------
        # 1. INPUT VALIDATION & RESOURCE POLICY
        # -------------------------------------------------------------
        notify("Validating input artifacts and resource policies...", 1)
        p_sample = Path(sample_path) if sample_path else None
        p_pcap = Path(pcap_path) if pcap_path else None
        p_procmon = Path(procmon_path) if procmon_path else None
        p_regshot = Path(regshot_path) if regshot_path else None
        p_yara_rules = Path(yara_rules) if yara_rules else None

        if not p_sample and not p_pcap and not p_procmon and not p_regshot:
            raise ValueError("At least one input artifact (--sample, --pcap, or --procmon) is required.")

        # Portable mode guarantees: offline, no remote AI, strict privacy, sanitized machine paths
        if portable:
            offline = True
            privacy_mode = "strict"

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

        # -------------------------------------------------------------
        # 2. MANIFEST & OUTPUT DIRECTORY INITIALIZATION
        # -------------------------------------------------------------
        notify("Initializing Evidence Store and Analysis Manifest...", 2)
        prof_cfg = get_profile(profile)
        
        # In strict/standard privacy or portable mode, sanitize host paths recorded in CLI arguments
        def sanitize_path(p: Optional[Path]) -> Optional[str]:
            if not p:
                return None
            if privacy_mode in ("strict", "standard") or portable:
                return p.name
            return str(p)

        manifest = AnalysisManifest(
            privacy_mode=privacy_mode,
            profile=prof_cfg.name.value if not adaptive else "adaptive",
            cli_arguments={
                "sample": sanitize_path(p_sample),
                "pcap": sanitize_path(p_pcap),
                "procmon": sanitize_path(p_procmon),
                "regshot": sanitize_path(p_regshot),
                "profile": profile,
                "privacy": privacy_mode,
                "offline": offline,
                "adaptive": adaptive,
                "portable": portable,
                "backend": backend,
                "yara_rules": sanitize_path(p_yara_rules),
                "export_raw_evidence": export_raw_evidence
            }
        )
        manifest.warnings.extend(warnings)

        # Destination Directory (Case-scoped if using default output directory - Phase 14)
        if output_dir:
            out_dir = Path(output_dir)
        else:
            base_out = get_output_dir()
            out_dir = base_out / manifest.case_id
        out_dir.mkdir(parents=True, exist_ok=True)
        manifest.resource_limits = {
            "max_sample_size": self.resource_policy.max_sample_size,
            "max_pcap_size": self.resource_policy.max_pcap_size,
            "max_packets": self.resource_policy.max_packets,
            "max_log_rows": self.resource_policy.max_log_rows,
            "max_stdout_bytes": getattr(self.resource_policy, "max_stdout_bytes", 5 * 1024 * 1024),
            "max_stderr_bytes": getattr(self.resource_policy, "max_stderr_bytes", 2 * 1024 * 1024),
            "analysis_timeout": self.resource_policy.analysis_timeout
        }

        # Record input artifact streaming hashes into manifest
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
        # 3. EVIDENCE STORE INITIALIZATION (Scalable Memory or SQLite)
        # -------------------------------------------------------------
        db_file = str(out_dir / "evidence.db") if backend == "sqlite" else None
        evidence_store = EvidenceStore(backend=backend, db_path=db_file)
        privacy_redactor = PrivacyRedactor(mode=privacy_mode)

        # -------------------------------------------------------------
        # 4. REPUTATION ANALYSIS STAGE (Between HASH and STATIC - Phase 2)
        # -------------------------------------------------------------
        sample_sha256 = manifest.sample_hashes.get("sha256", "")
        if p_sample and sample_sha256:
            notify("Checking hash reputation (VirusTotal hash lookup only)...", 3)
            rep_stage = ReputationStage(offline=offline or portable)
            t0 = time.perf_counter()
            rep_res = rep_stage.analyze(sample_sha256, evidence_store=evidence_store, artifact_name=p_sample.name)
            manifest.reputation = rep_res.model_dump()
            manifest.record_timing("ReputationStage", (time.perf_counter() - t0) * 1000.0)
            manifest.analyzers_enabled.append("ReputationStage")
        else:
            manifest.analyzers_skipped.append("ReputationStage")

        # -------------------------------------------------------------
        # 5. ANALYZERS EXECUTION (Static, Code, Behavioral, Adapters)
        # -------------------------------------------------------------
        static_data: Dict[str, Any] = {}
        code_data: Dict[str, Any] = {}
        behavioral_data: Dict[str, Any] = {}

        # 5a. Static PE Analyzer
        if p_sample and prof_cfg.enable_static:
            notify("Executing static PE analysis and section entropy triage...", 4)
            t0 = time.perf_counter()
            static_analyzer = PEStaticAnalyzer(p_sample, evidence_store=evidence_store)
            static_data = static_analyzer.analyze()
            manifest.record_timing("PEStaticAnalyzer", (time.perf_counter() - t0) * 1000.0)
            manifest.analyzers_enabled.append("PEStaticAnalyzer")

            if prof_cfg.enable_code:
                notify("Executing static code triage (Capstone entry-point disassembly)...", 4)
                t0 = time.perf_counter()
                code_analyzer = CodeAnalyzer(p_sample, evidence_store=evidence_store)
                code_data = code_analyzer.analyze()
                manifest.record_timing("CodeAnalyzer", (time.perf_counter() - t0) * 1000.0)
                manifest.analyzers_enabled.append("CodeAnalyzer")
            else:
                manifest.analyzers_skipped.append("CodeAnalyzer")
        else:
            manifest.analyzers_skipped.extend(["PEStaticAnalyzer", "CodeAnalyzer"])

        # 4b. Behavioral Telemetry (PCAP, Procmon, Regshot)
        if prof_cfg.enable_behavioral and (p_pcap or p_procmon or p_regshot):
            notify("Ingesting behavioral telemetry (PCAP streaming & Procmon logs)...", 5)
            t0 = time.perf_counter()
            beh_analyzer = BehavioralAnalyzer(
                pcap_path=str(p_pcap) if p_pcap else None,
                procmon_path=str(p_procmon) if p_procmon else None,
                regshot_path=str(p_regshot) if p_regshot else None,
                evidence_store=evidence_store
            )
            behavioral_data = beh_analyzer.analyze()
            manifest.record_timing("BehavioralAnalyzer", (time.perf_counter() - t0) * 1000.0)
            manifest.analyzers_enabled.append("BehavioralAnalyzer")
        else:
            manifest.analyzers_skipped.append("BehavioralAnalyzer")

        # 4c. Optional Integrations (Adaptive / Profile allowed)
        if p_sample:
            # Determine active tools: if adaptive, inspect host capabilities
            if adaptive:
                caps = CapabilityRegistry.get_capabilities()
                target_tools = [
                    tool_name for tool_name, info in caps.items()
                    if tool_name in ADAPTER_REGISTRY and (
                        not portable or info.get("tier", "").startswith("Tier 2")
                    ) and info.get("status") in ("FUNCTIONAL", "READY", "DETECTED")
                ]
            else:
                target_tools = [
                    t for t in prof_cfg.allowed_integrations
                    if not (portable and t in ("IDA Pro", "x64dbg", "WinDbg"))
                ]

            for tool_name in ADAPTER_REGISTRY:
                adapter_cls = ADAPTER_REGISTRY[tool_name]
                adapter = adapter_cls()

                if tool_name in target_tools and adapter.available():
                    notify(f"Running integration adapter: {tool_name}...", 6)
                    # Pass specific configuration overrides
                    kwargs: Dict[str, Any] = {}
                    if tool_name == "YARA" and p_yara_rules:
                        kwargs["rules_path"] = p_yara_rules

                    adapter_result = adapter.execute(p_sample, evidence_store=evidence_store, **kwargs)
                    manifest.record_adapter_result(adapter_result)
                    manifest.record_timing(f"adapter_{tool_name}", adapter_result.duration_ms)
                    manifest.analyzers_enabled.append(tool_name)
                    manifest.adapter_versions[tool_name] = adapter.version
                    if adapter_result.errors:
                        manifest.errors.extend(adapter_result.errors)
                    if adapter_result.warnings:
                        manifest.warnings.extend(adapter_result.warnings)
                else:
                    manifest.analyzers_skipped.append(tool_name)

        # -------------------------------------------------------------
        # 5. FINDING ENGINE CORRELATION
        # -------------------------------------------------------------
        notify("Correlating evidence facts into calibrated findings...", 7)
        finding_engine = FindingEngine(evidence_store)
        raw_findings = finding_engine.analyze()

        # -------------------------------------------------------------
        # 6. VALIDATION (Grounding check)
        # -------------------------------------------------------------
        validated_findings, finding_warnings = validate_finding_evidence_grounding(raw_findings, evidence_store)
        manifest.warnings.extend(finding_warnings)

        # -------------------------------------------------------------
        # 7. DETERMINISTIC ASSESSMENT
        # -------------------------------------------------------------
        notify("Computing deterministic assessment & explainable score...", 8)
        assessment = finding_engine.assess(validated_findings)

        # -------------------------------------------------------------
        # 8. PRIVACY REDACTION & DLP BOUNDARY (Phase 3)
        # -------------------------------------------------------------
        notify("Enforcing privacy/DLP security boundary...", 10)

        # Resolve provider and API key from argument or environment variables
        effective_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        is_remote = False
        llm_provider = "offline"

        if not (offline or prof_cfg.force_offline_ai):
            if effective_key:
                llm_provider = "openai" if (api_key or os.getenv("OPENAI_API_KEY")) else "anthropic"
                is_remote = True
            elif os.getenv("OLLAMA_HOST") or os.getenv("OPENAI_API_BASE"):
                llm_provider = "ollama"
                is_remote = True

        if is_remote:
            evidence_summary = evidence_store.to_dict()
            sanitized_evidence = privacy_redactor.redact(evidence_summary)
            sanitized_findings = privacy_redactor.redact([f.model_dump() for f in validated_findings])
            transmission_payload = {
                "provider": llm_provider,
                "model": model,
                "evidence": sanitized_evidence,
                "findings": sanitized_findings
            }

            audit_res = privacy_redactor.audit_for_transmission(transmission_payload)
            if not audit_res.is_safe or audit_res.status == DLPStatus.BLOCKED:
                manifest.warnings.append(
                    f"{BLOCK_REMOTE_TRANSMISSION}: Sensitive telemetry detected ({'; '.join(audit_res.violations)}). "
                    f"Blocked remote transmission; fallback to offline AI."
                )
                llm_provider = "offline"
                effective_key = None

        manifest.ai_mode = llm_provider

        # -------------------------------------------------------------
        # 9. OPTIONAL AI ENRICHMENT & AI VALIDATION
        # -------------------------------------------------------------
        notify("Synthesizing threat assessment (AI / Heuristic)...", 11)
        synthesizer = LLMThreatSynthesizer(
            provider=llm_provider,
            api_key=effective_key,
            model=model,
            privacy_mode=privacy_mode
        )
        assessment = synthesizer.synthesize(evidence_store, validated_findings, base_assessment=assessment)
        manifest.ai_metadata = {
            "provider": llm_provider,
            "model": model,
            "prompt_version": "1.0.0",
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "privacy_mode": privacy_mode,
            "remote_mode": "remote" if is_remote else "local",
            "validation_status": getattr(assessment, "validation_status", "VALIDATED")
        }
        manifest.configuration_hash = hashlib.sha256(
            f"{profile}:{privacy_mode}:{offline}:{adaptive}:{portable}".encode("utf-8")
        ).hexdigest()[:16]

        # -------------------------------------------------------------
        # 10. MULTI-FORMAT DELIVERABLE GENERATION
        # -------------------------------------------------------------
        notify("Compiling deliverables (JSON, Markdown, DOCX, Evidence, Findings)...", 12)

        # Build structured Evidence Appendix for auditable reporting (Phase 20)
        ev_map = {e.evidence_id: e for e in evidence_store.all()}
        evidence_appendix = []
        for f in validated_findings:
            artifacts = set()
            provenance_list = []
            rules = set()
            for eid in f.source_evidence_ids:
                rec = ev_map.get(eid)
                if rec:
                    artifacts.add(rec.source_artifact or "N/A")
                    if rec.derivation_rule:
                        rules.add(rec.derivation_rule)
                    loc_parts = []
                    if rec.source_offset:
                        loc_parts.append(f"offset={rec.source_offset}")
                    if rec.source_line:
                        loc_parts.append(f"line={rec.source_line}")
                    if rec.source_packet_number:
                        loc_parts.append(f"packet={rec.source_packet_number}")
                    if rec.source_record_id:
                        loc_parts.append(f"record={rec.source_record_id}")
                    provenance_list.append({
                        "evidence_id": eid,
                        "source_type": rec.source_type,
                        "field": rec.field,
                        "location": ", ".join(loc_parts) if loc_parts else "N/A"
                    })
                else:
                    provenance_list.append({"evidence_id": eid, "location": "N/A"})

            evidence_appendix.append({
                "finding_id": f.finding_id,
                "status": f.evidence_level.value if hasattr(f.evidence_level, "value") else str(f.evidence_level),
                "confidence": f.confidence,
                "evidence_ids": f.source_evidence_ids,
                "source_artifacts": sorted(list(artifacts)) if artifacts else ["N/A"],
                "source_provenance": provenance_list,
                "derivation_rule": ", ".join(sorted(rules)) if rules else "Direct observation"
            })

        session_payload = {
            "manifest": manifest.model_dump(),
            "assessment": assessment.model_dump(),
            "findings": [f.model_dump() for f in validated_findings],
            "evidence_records": evidence_store.to_dict(),
            "evidence_appendix": evidence_appendix,
            "coverage": assessment.coverage,
            "raw_telemetry": {
                "static": static_data,
                "code_analysis": code_data,
                "behavioral": behavioral_data
            }
        }
        sanitized_payload = privacy_redactor.redact(session_payload)

        # -------------------------------------------------------------
        # Phase 20: Case Bundle Layout (CASE-ID/ structure)
        # -------------------------------------------------------------
        dir_input = out_dir / "input"
        dir_reputation = out_dir / "reputation"
        dir_basic = out_dir / "basic"
        dir_advanced = out_dir / "advanced"
        dir_evidence = out_dir / "evidence"
        dir_report = out_dir / "report"
        dir_manifest = out_dir / "manifest"

        for d in (dir_input, dir_reputation, dir_basic, dir_advanced, dir_evidence, dir_report, dir_manifest):
            d.mkdir(parents=True, exist_ok=True)

        # Save input metadata (do NOT copy original sample binary unless requested)
        input_meta_file = dir_input / "input_metadata.json"
        with open(input_meta_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(manifest.artifacts, indent=2))

        # Save reputation raw stage output
        rep_file = dir_reputation / "reputation.json"
        with open(rep_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(manifest.reputation or {}, indent=2))

        # Save basic triage summary
        basic_file = dir_basic / "basic_triage.json"
        with open(basic_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "static": static_data.get("file_info", {}),
                "sections_count": len(static_data.get("sections", [])),
                "imports_count": len(static_data.get("imports", {}))
            }, indent=2))

        # Save advanced triage summary
        adv_file = dir_advanced / "advanced_triage.json"
        with open(adv_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "code_analysis": code_data,
                "behavioral_events": len(behavioral_data.get("normalized_events", []))
            }, indent=2))

        # 1. JSON Report
        report_json_path = out_dir / "report.json"
        JSONReportAdapter().render(sanitized_payload, report_json_path)
        JSONReportAdapter().render(sanitized_payload, dir_report / "report.json")

        # 2. Markdown Report
        report_md_path = out_dir / "report.md"
        MarkdownReportAdapter().render(sanitized_payload, report_md_path)
        MarkdownReportAdapter().render(sanitized_payload, dir_report / "report.md")

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
        docx_adapter.render(sanitized_payload, dir_report / "report.docx")

        # 4. Evidence Store JSON export - Privacy-Safe by default (Phase 4)
        evidence_json_path = out_dir / "evidence.json"
        sanitized_evidence_records = privacy_redactor.redact(evidence_store.to_dict())
        evidence_json_text = json.dumps(sanitized_evidence_records, indent=2)
        with open(evidence_json_path, "w", encoding="utf-8") as f:
            f.write(evidence_json_text)
        with open(dir_evidence / "evidence.json", "w", encoding="utf-8") as f:
            f.write(evidence_json_text)

        # 5. Findings JSON export - Privacy-Safe by default (Phase 4)
        findings_json_path = out_dir / "findings.json"
        sanitized_findings_records = privacy_redactor.redact([f.model_dump() for f in validated_findings])
        findings_json_text = json.dumps(sanitized_findings_records, indent=2)
        with open(findings_json_path, "w", encoding="utf-8") as f:
            f.write(findings_json_text)
        with open(dir_report / "findings.json", "w", encoding="utf-8") as f:
            f.write(findings_json_text)

        # 6. Assessment JSON export - Privacy-Safe by default (Phase 4)
        assessment_json_path = out_dir / "assessment.json"
        sanitized_assessment_record = privacy_redactor.redact(assessment.model_dump())
        assessment_json_text = json.dumps(sanitized_assessment_record, indent=2)
        with open(assessment_json_path, "w", encoding="utf-8") as f:
            f.write(assessment_json_text)
        with open(dir_report / "assessment.json", "w", encoding="utf-8") as f:
            f.write(assessment_json_text)

        # 7. IOCs JSON export - Privacy-Safe by default (Phase 4)
        iocs_json_path = out_dir / "iocs.json"
        sanitized_iocs = privacy_redactor.redact({"host_iocs": assessment.host_iocs, "network_iocs": assessment.network_iocs})
        iocs_json_text = json.dumps(sanitized_iocs, indent=2)
        with open(iocs_json_path, "w", encoding="utf-8") as f:
            f.write(iocs_json_text)
        with open(dir_report / "iocs.json", "w", encoding="utf-8") as f:
            f.write(iocs_json_text)

        # 8. Coverage JSON export
        coverage_json_path = out_dir / "coverage.json"
        cov = getattr(assessment, "coverage", None)
        cov_dict = cov.model_dump() if hasattr(cov, "model_dump") else (cov if isinstance(cov, dict) else {})
        cov_json_text = json.dumps(cov_dict, indent=2)
        with open(coverage_json_path, "w", encoding="utf-8") as f:
            f.write(cov_json_text)
        with open(dir_report / "coverage.json", "w", encoding="utf-8") as f:
            f.write(cov_json_text)

        # Opt-in Raw Evidence Export (Phase 4)
        raw_evidence_json_path = None
        if export_raw_evidence:
            raw_evidence_json_path = out_dir / "evidence.raw.json"
            evidence_store.export(raw_evidence_json_path)
            evidence_store.export(dir_evidence / "evidence.raw.json")
            manifest.record_output_artifact("evidence.raw.json", raw_evidence_json_path)

        # 9. Ensure artifacts and figures directories exist
        (out_dir / "artifacts").mkdir(parents=True, exist_ok=True)
        (out_dir / "figures").mkdir(parents=True, exist_ok=True)

        # -------------------------------------------------------------
        # 11. OUTPUT LINEAGE & MANIFEST INTEGRITY (No self-hashing)
        # -------------------------------------------------------------
        notify("Finalizing audit manifest and output lineage hashes...", 13)
        manifest_json_path = out_dir / "analysis_manifest.json"
        
        # Record output artifact lineage strictly excluding self-referential manifest files
        manifest.record_output_artifact("report.json", report_json_path)
        manifest.record_output_artifact("report.md", report_md_path)
        manifest.record_output_artifact("report.docx", report_docx_path)
        manifest.record_output_artifact("evidence.json", evidence_json_path)
        manifest.record_output_artifact("findings.json", findings_json_path)
        manifest.record_output_artifact("assessment.json", assessment_json_path)
        manifest.record_output_artifact("iocs.json", iocs_json_path)
        manifest.record_output_artifact("coverage.json", coverage_json_path)
        if raw_evidence_json_path and raw_evidence_json_path.exists():
            manifest.record_output_artifact("evidence.raw.json", raw_evidence_json_path)

        manifest.complete()
        companion_sha256_path = manifest.export_json(manifest_json_path)
        manifest.export_json(dir_manifest / "analysis_manifest.json")

        notify("Triage pipeline complete!", 14)

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
            manifest_sha256=companion_sha256_path,
            assessment_json=assessment_json_path,
            iocs_json=iocs_json_path,
            coverage_json=coverage_json_path,
            evidence_raw_json=raw_evidence_json_path,
            warnings=manifest.warnings
        )

    # Developer ergonomics alias
    analyze = run

