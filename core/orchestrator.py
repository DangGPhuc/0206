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
import shutil
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
from core.schemas import TransmissionMode, AnalysisDomain
from core.manifest import AnalysisManifest
from core.privacy import PrivacyMode, PrivacyRedactor, BLOCK_REMOTE_TRANSMISSION, DLPStatus
from core.atomic_io import atomic_write_json, atomic_write_text, set_posix_permissions
from core.validators import validate_finding_evidence_grounding
from integrations.registry import CapabilityRegistry

from analyzers.reputation.stage import ReputationStage
from analyzers.static.pe_analyzer import PEStaticAnalyzer
from analyzers.behavioral.event_normalizer import BehavioralAnalyzer
from analyzers.code.capstone_triage import CodeAnalyzer
from ai.agent import LLMThreatSynthesizer
from integrations.adapters import ADAPTER_REGISTRY
from sandbox.schema import SandboxGuestConfig, SandboxExecutionTrace, SandboxNetworkState, SandboxStatus
from sandbox.controller import SandboxController

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
    sandbox_trace: Optional[SandboxExecutionTrace] = None
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
        model: Optional[str] = None,
        template_path: Optional[str | Path] = None,
        yara_rules: Optional[str | Path] = None,
        backend: str = "memory",
        adaptive: bool = False,
        portable: bool = False,
        export_raw_evidence: bool = False,
        step_callback: Optional[Callable[[str, int], None]] = None,
        detonate: bool = False,
        sandbox_backend: Optional[str] = None,
        sandbox_config: Optional[SandboxGuestConfig] = None
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

        if detonate and not p_sample:
            raise ValueError("Live detonation requested (--detonate) but no sample PE binary was provided.")

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
        if p_regshot:
            ok, err = self.resource_policy.check_regshot(p_regshot)
            if not ok:
                warnings.append(err or "Regshot resource limit exceeded")

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
                "export_raw_evidence": export_raw_evidence,
                "detonate": detonate,
                "sandbox_backend": sandbox_backend
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
        set_posix_permissions(out_dir, 0o700)
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

        # 4b. Live Sandbox Detonation (Fail-Closed SandboxController)
        sandbox_trace: Optional[SandboxExecutionTrace] = None
        if detonate and p_sample:
            notify("Executing fail-closed live sandbox detonation...", 5)
            s_backend_type = sandbox_backend or "virtualbox"
            controller = SandboxController(config=sandbox_config, backend_type=s_backend_type)
            dir_sandbox_temp = out_dir / "sandbox"
            dir_sandbox_temp.mkdir(parents=True, exist_ok=True)
            t0 = time.perf_counter()
            sandbox_trace = controller.run_safe_session(str(p_sample), str(dir_sandbox_temp))
            manifest.record_timing("SandboxController", (time.perf_counter() - t0) * 1000.0)
            manifest.sandbox_provider = sandbox_trace.backend_name
            manifest.sandbox_network_mode = sandbox_trace.sandbox_network_mode or sandbox_trace.network_mode
            manifest.sandbox_network_verification_status = sandbox_trace.network_verification_status
            manifest.network_mode = sandbox_trace.network_mode
            manifest.snapshot_identifier = sandbox_trace.snapshot_name
            manifest.snapshot_uuid = sandbox_trace.baseline_snapshot_uuid
            manifest.telemetry_hashes = dict(sandbox_trace.telemetry_hashes)

            if sandbox_trace.errors:
                manifest.errors.extend(sandbox_trace.errors)
            if sandbox_trace.warnings:
                manifest.warnings.extend(sandbox_trace.warnings)

            # Record sandbox provenance EvidenceRecords into EvidenceStore (non-malicious facts)
            evidence_store.create(
                source_artifact="sandbox",
                source_type="SANDBOX_PROVENANCE",
                field="backend",
                value=sandbox_trace.backend_name,
                extractor="SandboxController",
                confidence=1.0,
                domain=AnalysisDomain.PROCESS
            )
            evidence_store.create(
                source_artifact="sandbox",
                source_type="SANDBOX_PROVENANCE",
                field="vm_name",
                value=sandbox_trace.vm_name,
                extractor="SandboxController",
                confidence=1.0,
                domain=AnalysisDomain.PROCESS
            )
            evidence_store.create(
                source_artifact="sandbox",
                source_type="SANDBOX_PROVENANCE",
                field="snapshot_name",
                value=sandbox_trace.snapshot_name,
                extractor="SandboxController",
                confidence=1.0,
                domain=AnalysisDomain.PROCESS
            )
            evidence_store.create(
                source_artifact="sandbox",
                source_type="SANDBOX_PROVENANCE",
                field="snapshot_uuid",
                value=sandbox_trace.baseline_snapshot_uuid or "N/A",
                extractor="SandboxController",
                confidence=1.0,
                domain=AnalysisDomain.PROCESS
            )
            evidence_store.create(
                source_artifact="sandbox",
                source_type="SANDBOX_PROVENANCE",
                field="sandbox_network_mode",
                value=sandbox_trace.sandbox_network_mode or sandbox_trace.network_mode,
                extractor="SandboxController",
                confidence=1.0,
                domain=AnalysisDomain.NETWORK
            )
            evidence_store.create(
                source_artifact="sandbox",
                source_type="SANDBOX_PROVENANCE",
                field="verified_network_mode",
                value=sandbox_trace.network_verification_status,
                extractor="SandboxController",
                confidence=1.0,
                domain=AnalysisDomain.NETWORK
            )
            evidence_store.create(
                source_artifact="sandbox",
                source_type="SANDBOX_PROVENANCE",
                field="trace_id",
                value=sandbox_trace.trace_id,
                extractor="SandboxController",
                confidence=1.0,
                domain=AnalysisDomain.PROCESS
            )
            evidence_store.create(
                source_artifact="sandbox",
                source_type="SANDBOX_PROVENANCE",
                field="execution_duration",
                value=sandbox_trace.execution_duration,
                extractor="SandboxController",
                confidence=1.0,
                domain=AnalysisDomain.PROCESS
            )
            evidence_store.create(
                source_artifact="sandbox",
                source_type="SANDBOX_PROVENANCE",
                field="telemetry_artifact_hashes",
                value=sandbox_trace.telemetry_hashes,
                extractor="SandboxController",
                confidence=1.0,
                domain=AnalysisDomain.PROCESS
            )

            # Gate BehavioralAnalyzer telemetry ingestion (Requirement 6)
            # Before BehavioralAnalyzer ingestion require:
            # - current trace_id (non-empty)
            # - execution_metadata.trace_id matches sandbox_trace.trace_id
            # - execution_metadata.sample_sha256 matches current sample SHA256
            # - telemetry SHA256 exists in sandbox_trace.telemetry_hashes
            # - calculated SHA256 equals trace SHA256
            # Do not ingest a file merely because expected_sha is missing.
            is_trace_eligible = (
                sandbox_trace.status not in (SandboxStatus.FAILED, SandboxStatus.NOT_EXECUTED)
                and bool(sandbox_trace.trace_id)
            )

            metadata_bound = False
            if is_trace_eligible:
                if sandbox_trace.execution_metadata_path and Path(sandbox_trace.execution_metadata_path).exists():
                    try:
                        meta_data = json.loads(Path(sandbox_trace.execution_metadata_path).read_text(encoding="utf-8"))
                        meta_trace_id = meta_data.get("trace_id")
                        meta_sample_sha = meta_data.get("sample_sha256")

                        trace_id_matches = bool(meta_trace_id and meta_trace_id == sandbox_trace.trace_id)
                        sample_sha_matches = bool(meta_sample_sha and (not sample_sha256 or meta_sample_sha == sample_sha256))

                        if trace_id_matches and sample_sha_matches:
                            metadata_bound = True
                        else:
                            reasons = []
                            if not trace_id_matches:
                                reasons.append(f"trace_id mismatch ('{meta_trace_id}' != '{sandbox_trace.trace_id}')")
                            if not sample_sha_matches:
                                reasons.append(f"sample_sha256 mismatch ('{meta_sample_sha}' != '{sample_sha256}')")
                            manifest.warnings.append(f"Sandbox execution metadata binding rejected: {'; '.join(reasons)}.")
                    except Exception as ex:
                        manifest.warnings.append(f"Failed to parse execution metadata for telemetry binding: {ex}")
                else:
                    manifest.warnings.append("Sandbox execution metadata file missing: telemetry binding rejected.")

            if is_trace_eligible and metadata_bound:
                if sandbox_trace.pcap_path and Path(sandbox_trace.pcap_path).exists():
                    pcap_p = Path(sandbox_trace.pcap_path)
                    calc_sha = hashlib.sha256(pcap_p.read_bytes()).hexdigest()
                    expected_sha = sandbox_trace.telemetry_hashes.get("network.pcap")
                    if expected_sha and calc_sha == expected_sha:
                        p_pcap = pcap_p
                        manifest.record_artifact("pcap", p_pcap)
                    else:
                        manifest.warnings.append(
                            f"PCAP telemetry rejected: SHA256 mismatch or missing expected hash (calc={calc_sha}, expected={expected_sha})."
                        )

                if sandbox_trace.procmon_csv_path and Path(sandbox_trace.procmon_csv_path).exists():
                    procmon_p = Path(sandbox_trace.procmon_csv_path)
                    calc_sha = hashlib.sha256(procmon_p.read_bytes()).hexdigest()
                    expected_sha = sandbox_trace.telemetry_hashes.get("procmon.csv")
                    if expected_sha and calc_sha == expected_sha:
                        p_procmon = procmon_p
                        manifest.record_artifact("procmon", p_procmon)
                    else:
                        manifest.warnings.append(
                            f"Procmon telemetry rejected: SHA256 mismatch or missing expected hash (calc={calc_sha}, expected={expected_sha})."
                        )

                if sandbox_trace.regshot_path and Path(sandbox_trace.regshot_path).exists():
                    regshot_p = Path(sandbox_trace.regshot_path)
                    calc_sha = hashlib.sha256(regshot_p.read_bytes()).hexdigest()
                    expected_sha = sandbox_trace.telemetry_hashes.get("regshot.txt")
                    if expected_sha and calc_sha == expected_sha:
                        p_regshot = regshot_p
                        manifest.record_artifact("regshot", p_regshot)
                    else:
                        manifest.warnings.append(
                            f"Regshot telemetry rejected: SHA256 mismatch or missing expected hash (calc={calc_sha}, expected={expected_sha})."
                        )
            else:
                if not is_trace_eligible:
                    manifest.warnings.append(f"Sandbox telemetry ingestion blocked: session status is '{sandbox_trace.status}'.")

        # 4c. Behavioral Telemetry (PCAP, Procmon, Regshot)
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
        llm_provider = "offline"
        transmission_mode = TransmissionMode.OFFLINE
        effective_key = None

        if not (offline or prof_cfg.force_offline_ai):
            if api_key or os.getenv("OPENAI_API_KEY"):
                llm_provider = "openai"
                effective_key = api_key or os.getenv("OPENAI_API_KEY")
                transmission_mode = TransmissionMode.REMOTE_SERVICE
            elif os.getenv("ANTHROPIC_API_KEY"):
                llm_provider = "anthropic"
                effective_key = os.getenv("ANTHROPIC_API_KEY")
                transmission_mode = TransmissionMode.REMOTE_SERVICE
            elif os.getenv("OLLAMA_HOST") or os.getenv("OLLAMA_API_BASE"):
                llm_provider = "ollama"
                transmission_mode = TransmissionMode.LOCAL_SERVICE

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
            "provider": synthesizer.provider,
            "model": synthesizer.model,
            "prompt_version": "1.0.0",
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "privacy_mode": privacy_mode,
            "remote_mode": transmission_mode.value,
            "validation_status": getattr(assessment, "validation_status", "VALIDATED")
        }
        manifest.synthesizer = {
            "model": synthesizer.model,
            "provider": synthesizer.provider
        }

        s_cfg_str = f"{sandbox_backend or 'virtualbox'}:{getattr(sandbox_config, 'network_mode', 'ISOLATED')}" if detonate else "none"
        manifest.configuration_hash = hashlib.sha256(
            f"{profile}:{privacy_mode}:{offline}:{adaptive}:{portable}:{detonate}:{s_cfg_str}".encode("utf-8")
        ).hexdigest()[:16]

        # -------------------------------------------------------------
        # 10. CASE BUNDLE LAYOUT & ARTIFACT PERSISTENCE
        # -------------------------------------------------------------
        dir_input = out_dir / "input"
        dir_reputation = out_dir / "reputation"
        dir_basic = out_dir / "basic"
        dir_advanced = out_dir / "advanced"
        dir_evidence = out_dir / "evidence"
        dir_report = out_dir / "report"
        dir_manifest = out_dir / "manifest"
        dir_sandbox = out_dir / "sandbox"

        for d in (dir_input, dir_reputation, dir_basic, dir_advanced, dir_evidence, dir_report, dir_manifest):
            d.mkdir(parents=True, exist_ok=True)
            set_posix_permissions(d, 0o700)

        # Create sanitized views of raw telemetry before persistence (Priority 3)
        safe_static_data = privacy_redactor.redact(static_data)
        safe_code_data = privacy_redactor.redact(code_data)
        safe_behavioral_data = privacy_redactor.redact(behavioral_data)
        safe_reputation_data = privacy_redactor.redact(manifest.reputation or {})
        safe_artifacts_meta = privacy_redactor.redact(manifest.artifacts)

        # Save input metadata (do NOT copy original sample binary unless requested)
        input_meta_file = dir_input / "input_metadata.json"
        atomic_write_json(input_meta_file, safe_artifacts_meta)

        # Save reputation raw stage output
        rep_file = dir_reputation / "reputation.json"
        atomic_write_json(rep_file, safe_reputation_data)

        # Save basic triage summary
        basic_file = dir_basic / "basic_triage.json"
        atomic_write_json(basic_file, {
            "static": safe_static_data.get("file_info", {}),
            "sections_count": len(safe_static_data.get("sections", [])),
            "imports_count": len(safe_static_data.get("imports", {}))
        })

        # Save advanced triage summary
        adv_file = dir_advanced / "advanced_triage.json"
        atomic_write_json(adv_file, {
            "code_analysis": safe_code_data,
            "behavioral_events": len(safe_behavioral_data.get("normalized_events", []))
        })

        # Save sandbox artifacts in case/sandbox/ and record lineage BEFORE report generation (Requirement 12)
        if sandbox_trace:
            dir_sandbox.mkdir(parents=True, exist_ok=True)
            set_posix_permissions(dir_sandbox, 0o700)
            safe_sandbox_trace = privacy_redactor.redact(sandbox_trace.model_dump())
            trace_file = dir_sandbox / "sandbox_trace.json"
            atomic_write_json(trace_file, safe_sandbox_trace)
            set_posix_permissions(trace_file, 0o600)
            manifest.record_output_artifact("sandbox/sandbox_trace.json", trace_file)
            manifest.sandbox_trace_hash = manifest.output_lineage.get("sandbox/sandbox_trace.json", {}).get("sha256")

            if sandbox_trace.execution_metadata_path and Path(sandbox_trace.execution_metadata_path).exists():
                meta_src = Path(sandbox_trace.execution_metadata_path)
                meta_dst = dir_sandbox / "execution_metadata.json"
                if meta_src.resolve() != meta_dst.resolve():
                    shutil.copy2(meta_src, meta_dst)
                set_posix_permissions(meta_dst, 0o600)
                manifest.record_output_artifact("sandbox/execution_metadata.json", meta_dst)

            if sandbox_trace.procmon_csv_path and Path(sandbox_trace.procmon_csv_path).exists():
                p_src = Path(sandbox_trace.procmon_csv_path)
                p_dst = dir_sandbox / "procmon.csv"
                if p_src.resolve() != p_dst.resolve():
                    shutil.copy2(p_src, p_dst)
                set_posix_permissions(p_dst, 0o600)
                manifest.record_output_artifact("sandbox/procmon.csv", p_dst)

            if sandbox_trace.pcap_path and Path(sandbox_trace.pcap_path).exists():
                p_src = Path(sandbox_trace.pcap_path)
                p_dst = dir_sandbox / "network.pcap"
                if p_src.resolve() != p_dst.resolve():
                    shutil.copy2(p_src, p_dst)
                set_posix_permissions(p_dst, 0o600)
                manifest.record_output_artifact("sandbox/network.pcap", p_dst)

            if sandbox_trace.regshot_path and Path(sandbox_trace.regshot_path).exists():
                r_src = Path(sandbox_trace.regshot_path)
                r_dst = dir_sandbox / "regshot.txt"
                if r_src.resolve() != r_dst.resolve():
                    shutil.copy2(r_src, r_dst)
                set_posix_permissions(r_dst, 0o600)
                manifest.record_output_artifact("sandbox/regshot.txt", r_dst)

        # 4. Evidence Store JSON export - Privacy-Safe by default (Phase 4)
        evidence_json_path = out_dir / "evidence.json"
        sanitized_evidence_records = privacy_redactor.redact(evidence_store.to_dict())
        atomic_write_json(evidence_json_path, sanitized_evidence_records)
        atomic_write_json(dir_evidence / "evidence.json", sanitized_evidence_records)
        manifest.record_output_artifact("evidence.json", evidence_json_path)

        # 5. Findings JSON export - Privacy-Safe by default (Phase 4)
        findings_json_path = out_dir / "findings.json"
        sanitized_findings_records = privacy_redactor.redact([f.model_dump() for f in validated_findings])
        atomic_write_json(findings_json_path, sanitized_findings_records)
        atomic_write_json(dir_report / "findings.json", sanitized_findings_records)
        manifest.record_output_artifact("findings.json", findings_json_path)

        # 6. Assessment JSON export - Privacy-Safe by default (Phase 4)
        assessment_json_path = out_dir / "assessment.json"
        sanitized_assessment_record = privacy_redactor.redact(assessment.model_dump())
        atomic_write_json(assessment_json_path, sanitized_assessment_record)
        atomic_write_json(dir_report / "assessment.json", sanitized_assessment_record)
        manifest.record_output_artifact("assessment.json", assessment_json_path)

        # 7. IOCs JSON export - Privacy-Safe by default (Phase 4)
        iocs_json_path = out_dir / "iocs.json"
        sanitized_iocs = privacy_redactor.redact({"host_iocs": assessment.host_iocs, "network_iocs": assessment.network_iocs})
        atomic_write_json(iocs_json_path, sanitized_iocs)
        atomic_write_json(dir_report / "iocs.json", sanitized_iocs)
        manifest.record_output_artifact("iocs.json", iocs_json_path)

        # 8. Coverage JSON export
        coverage_json_path = out_dir / "coverage.json"
        cov = getattr(assessment, "coverage", None)
        cov_dict = cov.model_dump() if hasattr(cov, "model_dump") else (cov if isinstance(cov, dict) else {})
        sanitized_cov = privacy_redactor.redact(cov_dict)
        atomic_write_json(coverage_json_path, sanitized_cov)
        atomic_write_json(dir_report / "coverage.json", sanitized_cov)
        manifest.record_output_artifact("coverage.json", coverage_json_path)

        # Opt-in Raw Evidence Export (Phase 4)
        raw_evidence_json_path = None
        if export_raw_evidence:
            raw_evidence_json_path = out_dir / "evidence.raw.json"
            evidence_store.export(raw_evidence_json_path)
            evidence_store.export(dir_evidence / "evidence.raw.json")
            set_posix_permissions(raw_evidence_json_path, 0o600)
            set_posix_permissions(dir_evidence / "evidence.raw.json", 0o600)
            manifest.record_output_artifact("evidence.raw.json", raw_evidence_json_path)

        # -------------------------------------------------------------
        # 11. MULTI-FORMAT DELIVERABLE GENERATION
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
            "sandbox": {
                "backend": sandbox_trace.backend_name if sandbox_trace else "NOT_USED",
                "execution_status": sandbox_trace.execution_status if sandbox_trace else "NOT_ANALYZED",
                "network_mode": (sandbox_trace.sandbox_network_mode or sandbox_trace.network_mode) if sandbox_trace else "NOT_USED",
                "network_verification": sandbox_trace.network_verification_status if sandbox_trace else "UNVERIFIED",
                "snapshot_name": sandbox_trace.snapshot_name if sandbox_trace else "N/A",
                "snapshot_uuid": sandbox_trace.baseline_snapshot_uuid if sandbox_trace else "N/A",
                "revert_status": sandbox_trace.revert_status if sandbox_trace else "NOT_ANALYZED",
                "trace_hash": manifest.sandbox_trace_hash or "N/A",
                "telemetry_hashes": sandbox_trace.telemetry_hashes if sandbox_trace else {},
                "telemetry_available": {
                    "pcap": bool(sandbox_trace and sandbox_trace.pcap_path),
                    "procmon": bool(sandbox_trace and sandbox_trace.procmon_csv_path),
                    "regshot": bool(sandbox_trace and sandbox_trace.regshot_path)
                } if sandbox_trace else {},
                "execution_duration": sandbox_trace.execution_duration if sandbox_trace else 0.0,
                "limitations": (sandbox_trace.warnings + sandbox_trace.errors) if sandbox_trace else []
            },
            "raw_telemetry": {
                "static": safe_static_data,
                "code_analysis": safe_code_data,
                "behavioral": safe_behavioral_data
            }
        }
        sanitized_payload = privacy_redactor.redact(session_payload)

        # 1. JSON Report
        report_json_path = out_dir / "report.json"
        JSONReportAdapter().render(sanitized_payload, report_json_path)
        JSONReportAdapter().render(sanitized_payload, dir_report / "report.json")
        set_posix_permissions(report_json_path, 0o600)
        set_posix_permissions(dir_report / "report.json", 0o600)

        # 2. Markdown Report
        report_md_path = out_dir / "report.md"
        MarkdownReportAdapter().render(sanitized_payload, report_md_path)
        MarkdownReportAdapter().render(sanitized_payload, dir_report / "report.md")
        set_posix_permissions(report_md_path, 0o600)
        set_posix_permissions(dir_report / "report.md", 0o600)

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
        set_posix_permissions(report_docx_path, 0o600)
        set_posix_permissions(dir_report / "report.docx", 0o600)

        # Ensure artifacts and figures directories exist
        (out_dir / "artifacts").mkdir(parents=True, exist_ok=True)
        set_posix_permissions(out_dir / "artifacts", 0o700)
        (out_dir / "figures").mkdir(parents=True, exist_ok=True)
        set_posix_permissions(out_dir / "figures", 0o700)

        # -------------------------------------------------------------
        # 12. OUTPUT LINEAGE & MANIFEST INTEGRITY (No self-hashing)
        # -------------------------------------------------------------
        notify("Finalizing audit manifest and output lineage hashes...", 13)
        manifest_json_path = out_dir / "analysis_manifest.json"

        # Record report outputs in manifest lineage
        manifest.record_output_artifact("report.json", report_json_path)
        manifest.record_output_artifact("report.md", report_md_path)
        manifest.record_output_artifact("report.docx", report_docx_path)

        manifest.complete()
        companion_sha256_path = manifest.export_json(manifest_json_path)
        dir_manifest_sha = manifest.export_json(dir_manifest / "analysis_manifest.json")
        set_posix_permissions(manifest_json_path, 0o600)
        set_posix_permissions(companion_sha256_path, 0o600)
        set_posix_permissions(dir_manifest / "analysis_manifest.json", 0o600)
        set_posix_permissions(dir_manifest_sha, 0o600)


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
            sandbox_trace=sandbox_trace,
            warnings=manifest.warnings
        )

    # Developer ergonomics alias
    analyze = run

