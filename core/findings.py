"""
0206 - Findings and Assessment Layer
Strictly separates raw Evidence (facts), Findings (inferences), and Assessments (evaluations).
Integrates CorrelationEngine for cross-stage corroboration and AssessmentEngine for explainable scoring.
Enforces calibrated threat attribution without ungrounded overclaims.
"""
from typing import Any, Dict, List, Optional
import json
from pathlib import Path

from core.evidence import EvidenceStore
from core.schemas import (
    AnalysisDomain, EvidenceState, Finding, FindingStatus, FindingSeverity,
    FindingCategory, Classification, ScoreContribution, Assessment
)
from core.correlation import CorrelationEngine
from core.assessment import AssessmentEngine


CATEGORY_TO_DOMAIN = {
    FindingCategory.PACKING_AND_OBFUSCATION: (AnalysisDomain.PACKING, [AnalysisDomain.OBFUSCATION]),
    FindingCategory.API_RESOLUTION: (AnalysisDomain.API, [AnalysisDomain.ASSEMBLY, AnalysisDomain.OBFUSCATION]),
    FindingCategory.PROCESS_INJECTION: (AnalysisDomain.PROCESS, [AnalysisDomain.MEMORY]),
    FindingCategory.NETWORK_C2: (AnalysisDomain.C2, [AnalysisDomain.NETWORK]),
    FindingCategory.PERSISTENCE: (AnalysisDomain.PERSISTENCE, [AnalysisDomain.REGISTRY]),
    FindingCategory.DEFENSE_EVASION: (AnalysisDomain.ANTI_ANALYSIS, [AnalysisDomain.OBFUSCATION]),
    FindingCategory.DISASSEMBLY_ANOMALY: (AnalysisDomain.ASSEMBLY, [AnalysisDomain.CODE_EXECUTION]),
    FindingCategory.DATA_EXFILTRATION: (AnalysisDomain.NETWORK, [AnalysisDomain.FILESYSTEM]),
    FindingCategory.HOST_TAMPERING: (AnalysisDomain.FILESYSTEM, [AnalysisDomain.PROCESS]),
    FindingCategory.CRYPTOGRAPHY: (AnalysisDomain.CRYPTOGRAPHY, [AnalysisDomain.OBFUSCATION]),
    FindingCategory.FILE_IDENTIFICATION: (AnalysisDomain.PE, [AnalysisDomain.LOADER])
}


class FindingEngine:
    """
    Tier 2: Finding Correlation Engine.
    Correlates atomic EvidenceRecords across static, code, and behavioral analysis
    into verified Finding and Assessment objects with strict evidence grounding.
    """

    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store
        self.findings: List[Finding] = []
        self._counter = 1
        self.correlation_engine = CorrelationEngine(evidence_store)
        self.assessment_engine = AssessmentEngine(evidence_store)

    def _create_finding(
        self,
        category: FindingCategory,
        title: str,
        evidence_level: EvidenceState,
        confidence: float,
        details: str,
        source_evidence_ids: List[str],
        mitre_attack_id: Optional[str] = None,
        mitre_tactic: Optional[str] = None,
        domain: Optional[AnalysisDomain] = None,
        additional_domains: Optional[List[AnalysisDomain]] = None,
        status: FindingStatus = FindingStatus.CAPABILITY,
        why_it_matters: str = ""
    ) -> Optional[Finding]:
        valid_evidence_ids = [eid for eid in source_evidence_ids if self.evidence_store.get(eid)]

        if not valid_evidence_ids and evidence_level != EvidenceState.NOT_ANALYZED:
            return None

        fid = f"F-{self._counter:04d}"
        self._counter += 1

        primary_dom, default_add_doms = CATEGORY_TO_DOMAIN.get(category, (AnalysisDomain.PE, []))
        dom = domain or primary_dom
        add_doms = additional_domains or default_add_doms

        sev = FindingSeverity.MEDIUM
        if category in (FindingCategory.PROCESS_INJECTION, FindingCategory.NETWORK_C2, FindingCategory.PERSISTENCE):
            sev = FindingSeverity.HIGH

        f = Finding(
            finding_id=fid,
            domain=dom,
            additional_domains=add_doms,
            category=category,
            title=title,
            state=evidence_level,
            confidence=confidence,
            severity=sev,
            details=details,
            why_it_matters=why_it_matters,
            evidence_ids=valid_evidence_ids,
            mitre_attack_id=mitre_attack_id,
            mitre_tactic=mitre_tactic,
            status=status
        )
        self.findings.append(f)
        return f

    def analyze(self) -> List[Finding]:
        """Runs calibrated inference rules across stored evidence and applies cross-stage correlation."""
        self.findings.clear()

        # 1. RWX sections
        rwx_evs = self.evidence_store.find(field="section_is_rwx")
        rwx_active = [e for e in rwx_evs if e.value is True]
        if rwx_active:
            sec_names = [e.provenance.get("section_name", "unknown") for e in rwx_active]
            self._create_finding(
                category=FindingCategory.PACKING_AND_OBFUSCATION,
                title="RWX Section Detected (Writable & Executable)",
                evidence_level=EvidenceState.OBSERVED,
                confidence=0.95,
                details=(
                    f"Section(s) {', '.join(sec_names)} possess concurrent Read, Write, and Execute permissions. "
                    f"While this enables self-modifying code or unpacking stubs, runtime process injection is [NOT_CONFIRMED]."
                ),
                source_evidence_ids=[e.evidence_id for e in rwx_active],
                mitre_attack_id="T1027",
                mitre_tactic="Defense Evasion",
                status=FindingStatus.OBSERVED_BEHAVIOR,
                why_it_matters="Executable memory that is also writable provides an environment for self-modifying code or unpacked payload stubs; does not confirm process injection without active foreign process memory write."
            )

        # 2. Packing Indicators
        packing_evs = self.evidence_store.find(field="packer_assessment")
        for pe in packing_evs:
            val = pe.value if isinstance(pe.value, dict) else {}
            cls = val.get("classification", "NOT_DETECTED")
            if cls in ("POSSIBLE_PACKING", "LIKELY_PACKED", "UNPACKING_REQUIRED"):
                self._create_finding(
                    category=FindingCategory.PACKING_AND_OBFUSCATION,
                    title=f"Sample Packing Assessment: {cls}",
                    evidence_level=EvidenceState.INFERRED,
                    confidence=val.get("confidence", 0.7),
                    details=(
                        f"Heuristic packer score {val.get('score', 0)}/100. "
                        f"Indicators: {'; '.join(val.get('indicators', []))}. "
                        f"Caveats: {'; '.join(val.get('caveats', ['Entropy is an indicator, not cryptographic proof.']))}"
                    ),
                    source_evidence_ids=[pe.evidence_id],
                    mitre_attack_id="T1027.002",
                    mitre_tactic="Defense Evasion",
                    status=FindingStatus.CAPABILITY,
                    why_it_matters="Packed executables conceal original code flow and import dependencies, impeding static analysis."
                )

        # 3. API Hashing constants
        api_hash_evs = self.evidence_store.find(field="api_hash_match")
        if api_hash_evs:
            resolved = [f"{e.value.get('api')} ({e.value.get('algorithm')})" for e in api_hash_evs]
            self._create_finding(
                category=FindingCategory.API_RESOLUTION,
                title="Embedded Win32 API Hashing Constants",
                evidence_level=EvidenceState.OBSERVED,
                confidence=0.85,
                details=(
                    f"[OBSERVED_HASH_CONSTANT] Detected {len(api_hash_evs)} precomputed API hash constant(s) in binary bytes: "
                    f"{', '.join(resolved[:6])}. "
                    f"[NOT_CONFIRMED] Dynamic runtime resolution of these APIs was not verified."
                ),
                source_evidence_ids=[e.evidence_id for e in api_hash_evs],
                mitre_attack_id="T1027.007",
                mitre_tactic="Defense Evasion",
                status=FindingStatus.OBSERVED_BEHAVIOR,
                why_it_matters="API hashing bypasses static IAT inspection by resolving functions at runtime via precomputed hashes."
            )

        # 4. Process Injection APIs
        inj_apis = self.evidence_store.find(field="imported_api_injection")
        if inj_apis:
            api_names = [e.value for e in inj_apis]
            self._create_finding(
                category=FindingCategory.PROCESS_INJECTION,
                title="Potential Process Injection Capability (Static Import)",
                evidence_level=EvidenceState.INFERRED,
                confidence=0.70,
                details=(
                    f"Import Address Table contains APIs commonly utilized in process injection techniques: {', '.join(api_names)}. "
                    f"[NOT_CONFIRMED] Runtime execution of process injection was not observed."
                ),
                source_evidence_ids=[e.evidence_id for e in inj_apis],
                mitre_attack_id="T1055",
                mitre_tactic="Privilege Escalation / Defense Evasion",
                status=FindingStatus.CAPABILITY,
                why_it_matters="Injection APIs allow a process to allocate, write, and execute code within the address space of another process."
            )

        # 5. Network C2 / Periodic Beacons
        beacon_evs = self.evidence_store.find(field="beacon_analysis")
        for b in beacon_evs:
            b_val = b.value if isinstance(b.value, dict) else {}
            classification = b_val.get("classification", "NORMAL")
            if classification in (
                "OBSERVED_PERIODIC_TRAFFIC", "SUSPECTED_BEACONING", "LIKELY_C2_BEACON", "CONFIRMED_C2",
                "SUSPICIOUS", "LIKELY_BEACON", "HIGH_CONFIDENCE_BEACON"
            ):
                is_confirmed = classification == "CONFIRMED_C2"
                ev_state = EvidenceState.OBSERVED if is_confirmed else (
                    EvidenceState.HEURISTIC if classification == "OBSERVED_PERIODIC_TRAFFIC" else EvidenceState.INFERRED
                )
                title = f"Confirmed C2 Channel ({b_val.get('destination_ip')})" if is_confirmed else f"Network Beaconing ({classification}): {b_val.get('destination_ip')}"
                note = "Multi-source corroborated C2 communication channel." if is_confirmed else "Statistical periodicity observed; protocol content not independently confirmed malicious."
                self._create_finding(
                    category=FindingCategory.NETWORK_C2,
                    title=title,
                    evidence_level=ev_state,
                    confidence=b_val.get("beacon_score", 0.6),
                    details=(
                        f"Destination {b_val.get('destination_ip')}:{b_val.get('destination_port')} exhibited periodic network connections. "
                        f"Interval: avg={b_val.get('avg_interval', 0):.2f}s, jitter={b_val.get('jitter_ratio', 0):.2f}, "
                        f"Composite Score={b_val.get('beacon_score', 0):.2f}. [{classification}] {note}"
                    ),
                    source_evidence_ids=[b.evidence_id],
                    mitre_attack_id="T1071",
                    mitre_tactic="Command and Control",
                    status=FindingStatus.CONFIRMED_BEHAVIOR if is_confirmed else FindingStatus.OBSERVED_BEHAVIOR,
                    why_it_matters="Periodic beaconing traffic is characteristic of remote command-and-control communication channels."
                )

        # 6. Host Persistence (Procmon / Regshot)
        reg_pers_evs = self.evidence_store.find(field="registry_persistence")
        if reg_pers_evs:
            keys = [e.value.get("key_path", "") for e in reg_pers_evs]
            self._create_finding(
                category=FindingCategory.PERSISTENCE,
                title="Registry Autostart Persistence Modification",
                evidence_level=EvidenceState.OBSERVED,
                confidence=0.95,
                details=f"Sample established or modified Windows Autostart Run key(s): {', '.join(keys)}",
                source_evidence_ids=[e.evidence_id for e in reg_pers_evs],
                mitre_attack_id="T1547.001",
                mitre_tactic="Persistence",
                status=FindingStatus.OBSERVED_BEHAVIOR,
                why_it_matters="Autostart Run keys ensure that the malware payload executes automatically upon user logon."
            )

        # 7. Dropped Files
        dropped_evs = self.evidence_store.find(field="dropped_file")
        if dropped_evs:
            paths = [e.value.get("path", "") for e in dropped_evs]
            self._create_finding(
                category=FindingCategory.HOST_TAMPERING,
                title="Executable Dropped to Host Filesystem",
                evidence_level=EvidenceState.OBSERVED,
                confidence=0.90,
                details=f"Process dropped binary file(s) to disk during telemetry monitoring: {', '.join(paths)}",
                source_evidence_ids=[e.evidence_id for e in dropped_evs],
                mitre_attack_id="T1105",
                mitre_tactic="Command and Control / Execution",
                status=FindingStatus.OBSERVED_BEHAVIOR,
                why_it_matters="Dropping files to user or temp directories is a common initial staging technique for multi-stage payloads."
            )

        # Apply cross-stage correlation rules across established findings
        self.findings = self.correlation_engine.correlate(self.findings)
        return self.findings

    def assess(self, findings: Optional[List[Finding]] = None) -> Assessment:
        """Evaluates findings and computes deterministic threat assessment."""
        target_findings = findings if findings is not None else self.findings
        return self.assessment_engine.assess(target_findings)

    def generate_assessment(self) -> Assessment:
        """Legacy backward-compatible alias."""
        if not self.findings:
            self.analyze()
        return self.assess(self.findings)

    def to_dict(self) -> List[Dict[str, Any]]:
        return [f.model_dump() for f in self.findings]

    def export(self, output_path: Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return output_path
