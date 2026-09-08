"""
0206 - Findings and Assessment Layer
Strictly separates raw Evidence (facts), Findings (inferences), and Assessments (evaluations).
"""
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from core.evidence import EvidenceState, EvidenceStore


class FindingCategory(str, Enum):
    FILE_IDENTIFICATION = "FILE_IDENTIFICATION"
    PACKING_AND_OBFUSCATION = "PACKING_AND_OBFUSCATION"
    API_RESOLUTION = "API_RESOLUTION"
    PROCESS_INJECTION = "PROCESS_INJECTION"
    PERSISTENCE = "PERSISTENCE"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    NETWORK_C2 = "NETWORK_C2"
    DISASSEMBLY_ANOMALY = "DISASSEMBLY_ANOMALY"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    HOST_TAMPERING = "HOST_TAMPERING"


class Finding(BaseModel):
    """
    Tier 2: Finding represents a correlated technical inference derived from one or more EvidenceRecords.
    Must cite source_evidence_ids.
    """
    finding_id: str
    category: FindingCategory
    title: str
    evidence_level: EvidenceState = EvidenceState.INFERRED
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    details: str
    source_evidence_ids: List[str] = Field(default_factory=list)
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    status: str = "ACTIVE"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    class Config:
        use_enum_values = True


class Assessment(BaseModel):
    """
    Tier 3: Strategic evaluation and contextual assessment synthesising multiple findings.
    Distinguishes observed facts from unconfirmed hypotheses.
    """
    assessment_id: str
    title: str
    threat_level: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    threat_score: int  # 0 to 100
    classification: str
    summary: str
    key_functionality: str
    purpose: str
    persistence_assessment: str
    runtime_confirmation_status: str  # CONFIRMED, NOT_CONFIRMED, NOT_ANALYZED
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    host_iocs: List[str] = Field(default_factory=list)
    network_iocs: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    supporting_finding_ids: List[str] = Field(default_factory=list)


class FindingEngine:
    """
    Deterministic inference engine that processes raw EvidenceRecords from an EvidenceStore
    into verified Finding and Assessment objects with strict evidence grounding.
    """

    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store
        self.findings: List[Finding] = []
        self._counter = 1

    def _create_finding(
        self,
        category: FindingCategory,
        title: str,
        evidence_level: EvidenceState,
        confidence: float,
        details: str,
        source_evidence_ids: List[str],
        mitre_attack_id: Optional[str] = None,
        mitre_tactic: Optional[str] = None
    ) -> Finding:
        # Validate that all cited evidence IDs exist
        valid_evidence_ids = []
        for eid in source_evidence_ids:
            if self.evidence_store.get(eid):
                valid_evidence_ids.append(eid)

        fid = f"F-{self._counter:04d}"
        self._counter += 1

        f = Finding(
            finding_id=fid,
            category=category,
            title=title,
            evidence_level=evidence_level,
            confidence=confidence,
            details=details,
            source_evidence_ids=valid_evidence_ids,
            mitre_attack_id=mitre_attack_id,
            mitre_tactic=mitre_tactic
        )
        self.findings.append(f)
        return f

    def analyze(self) -> List[Finding]:
        """Runs deterministic correlation rules across stored evidence."""
        self.findings.clear()

        # 1. Check for RWX sections
        rwx_evs = self.evidence_store.find(field="section_is_rwx")
        rwx_active = [e for e in rwx_evs if e.value is True]
        if rwx_active:
            sec_names = [e.provenance.get("section_name", "unknown") for e in rwx_active]
            self._create_finding(
                category=FindingCategory.PACKING_AND_OBFUSCATION,
                title="Executable Section with Writable Permissions (RWX)",
                evidence_level=EvidenceState.OBSERVED,
                confidence=0.95,
                details=f"Identified RWX memory permissions in section(s): {', '.join(sec_names)}. Highly indicative of unpacking stub or in-place code injection.",
                source_evidence_ids=[e.evidence_id for e in rwx_active],
                mitre_attack_id="T1055",
                mitre_tactic="Defense Evasion"
            )

        # 2. Check for Packing Indicators
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
                    details=f"Packer score {val.get('score', 0)}/100 based on indicators: {'; '.join(val.get('indicators', []))}. Caveats: {'; '.join(val.get('caveats', []))}",
                    source_evidence_ids=[pe.evidence_id],
                    mitre_attack_id="T1027.002",
                    mitre_tactic="Defense Evasion"
                )

        # 3. Check for API Hashing constants
        api_hash_evs = self.evidence_store.find(field="api_hash_match")
        if api_hash_evs:
            resolved = [f"{e.value.get('api')} ({e.value.get('algorithm')})" for e in api_hash_evs]
            self._create_finding(
                category=FindingCategory.API_RESOLUTION,
                title="Embedded Win32 API Hashing Constants",
                evidence_level=EvidenceState.OBSERVED,
                confidence=0.85,
                details=(
                    f"Detected {len(api_hash_evs)} precomputed API hash constant(s): {', '.join(resolved[:6])}. "
                    f"Note: [OBSERVED_HASH_CONSTANT] Constants observed statically. [NOT_CONFIRMED] Runtime resolution not dynamically verified."
                ),
                source_evidence_ids=[e.evidence_id for e in api_hash_evs],
                mitre_attack_id="T1027.007",
                mitre_tactic="Defense Evasion"
            )

        # 4. Check for Process Injection APIs
        inj_apis = self.evidence_store.find(field="imported_api_injection")
        if inj_apis:
            api_names = [e.value for e in inj_apis]
            self._create_finding(
                category=FindingCategory.PROCESS_INJECTION,
                title="Potential Process Injection APIs Imported",
                evidence_level=EvidenceState.INFERRED,
                confidence=0.75,
                details=(
                    f"Import Address Table contains APIs capable of memory allocation and thread creation in remote processes: {', '.join(api_names)}. "
                    f"[NOT_CONFIRMED] Runtime execution of injection was not verified dynamically."
                ),
                source_evidence_ids=[e.evidence_id for e in inj_apis],
                mitre_attack_id="T1055",
                mitre_tactic="Privilege Escalation / Defense Evasion"
            )

        # 5. Check for Network C2 / Periodic Beacons
        beacon_evs = self.evidence_store.find(field="beacon_analysis")
        for b in beacon_evs:
            b_val = b.value if isinstance(b.value, dict) else {}
            classification = b_val.get("classification", "NORMAL")
            if classification in ("SUSPICIOUS", "LIKELY_BEACON", "HIGH_CONFIDENCE_BEACON"):
                self._create_finding(
                    category=FindingCategory.NETWORK_C2,
                    title=f"Potential Periodic Network Beacon: {classification}",
                    evidence_level=EvidenceState.INFERRED,
                    confidence=b_val.get("beacon_score", 0.6),
                    details=(
                        f"Destination {b_val.get('destination_ip')} exhibited periodic connection intervals: "
                        f"Average interval: {b_val.get('avg_interval', 0):.2f}s, Jitter ratio: {b_val.get('jitter_ratio', 0):.2f}, "
                        f"Beacon composite score: {b_val.get('beacon_score', 0):.2f}. [SUSPECTED_C2] Runtime C2 confirmation pending protocol validation."
                    ),
                    source_evidence_ids=[b.evidence_id],
                    mitre_attack_id="T1071",
                    mitre_tactic="Command and Control"
                )

        # 6. Check for Dropped Binaries
        dropped_evs = self.evidence_store.find(field="dropped_file")
        if dropped_evs:
            paths = [e.value.get("path") for e in dropped_evs]
            self._create_finding(
                category=FindingCategory.HOST_TAMPERING,
                title="Executable Dropped to Host Filesystem",
                evidence_level=EvidenceState.OBSERVED,
                confidence=0.95,
                details=f"Observed file creation/write operations for binary payloads: {', '.join(paths[:4])}.",
                source_evidence_ids=[e.evidence_id for e in dropped_evs],
                mitre_attack_id="T1105",
                mitre_tactic="Command and Control"
            )

        # 7. Check for Registry Run Key Persistence
        pers_evs = self.evidence_store.find(field="registry_persistence")
        if pers_evs:
            keys = [e.value.get("key_path") for e in pers_evs]
            self._create_finding(
                category=FindingCategory.PERSISTENCE,
                title="Registry Autostart Persistence Modification",
                evidence_level=EvidenceState.OBSERVED,
                confidence=0.95,
                details=f"Detected autostart modification targeting registry Run/RunOnce key(s): {', '.join(keys[:4])}.",
                source_evidence_ids=[e.evidence_id for e in pers_evs],
                mitre_attack_id="T1547.001",
                mitre_tactic="Persistence"
            )

        return self.findings

    def generate_assessment(self) -> Assessment:
        """
        Synthesizes active findings into a final Assessment.
        Calculates threat level, extracts grounded IOCs, and maps MITRE techniques.
        """
        findings = self.findings if self.findings else self.analyze()

        score = 10
        mitre_map: Dict[str, Dict[str, str]] = {}
        host_iocs = set()
        network_iocs = set()
        supporting_fids = []

        # Extract IOCs from evidence store directly
        for e in self.evidence_store.all_records():
            if e.field == "sha256":
                host_iocs.add(f"SHA256: {e.value}")
            elif e.field == "imphash" and e.value != "N/A":
                host_iocs.add(f"Imphash: {e.value}")
            elif e.field == "dropped_file":
                host_iocs.add(f"Dropped File: {e.value.get('path')}")
            elif e.field == "registry_persistence":
                host_iocs.add(f"Run Key: {e.value.get('key_path')}")
            elif e.field == "dns_query":
                network_iocs.add(f"DNS Domain: {e.value.get('domain')}")
                for ip in e.value.get('resolved_ips', []):
                    network_iocs.add(f"Resolved IP: {ip}")
            elif e.field == "http_request":
                network_iocs.add(f"HTTP {e.value.get('method')}: http://{e.value.get('host')}{e.value.get('uri')}")

        for f in findings:
            supporting_fids.append(f.finding_id)
            if f.category == FindingCategory.PROCESS_INJECTION:
                score += 25
            elif f.category == FindingCategory.PERSISTENCE:
                score += 25
            elif f.category == FindingCategory.NETWORK_C2:
                score += 20
            elif f.category == FindingCategory.PACKING_AND_OBFUSCATION:
                score += 15
            elif f.category == FindingCategory.API_RESOLUTION:
                score += 15
            elif f.category == FindingCategory.HOST_TAMPERING:
                score += 15

            if f.mitre_attack_id:
                mitre_map[f.mitre_attack_id] = {
                    "technique_id": f.mitre_attack_id,
                    "technique_name": f.title,
                    "tactic": f.mitre_tactic or "Execution",
                    "evidence_ids": f.source_evidence_ids
                }

        threat_score = min(100, max(0, score))
        if threat_score >= 80:
            threat_level = "CRITICAL"
        elif threat_score >= 60:
            threat_level = "HIGH"
        elif threat_score >= 40:
            threat_level = "MEDIUM"
        elif threat_score >= 20:
            threat_level = "LOW"
        else:
            threat_level = "INFORMATIONAL / CLEAN"

        # Classification based on grounded findings
        has_inj = any(f.category == FindingCategory.PROCESS_INJECTION for f in findings)
        has_net = any(f.category == FindingCategory.NETWORK_C2 for f in findings)
        has_pers = any(f.category == FindingCategory.PERSISTENCE for f in findings)

        if has_inj and has_net:
            classification = "Trojan.Dropper / Injector / C2 Agent"
        elif has_net and not has_inj:
            classification = "Trojan.Downloader"
        elif has_pers:
            classification = "Backdoor / Persistent Trojan"
        else:
            classification = "Suspicious.PE.Generic"

        summary = (
            f"Automated evidence-grounded assessment evaluated {len(self.evidence_store)} forensic evidence records "
            f"and established {len(findings)} technical findings. Threat score is assessed at {threat_score}/100 ({threat_level}) "
            f"with classification '{classification}'."
        )

        key_func = (
            f"Observed capabilities include: "
            f"{'Process injection APIs detected (unconfirmed at runtime); ' if has_inj else ''}"
            f"{'Outbound periodic C2 beaconing observed; ' if has_net else ''}"
            f"{'Host persistence established via Registry Run keys; ' if has_pers else ''}"
            f"Evidence items are grounded in static and behavioral traces."
        )

        purpose = "Establish persistent access on host endpoint and establish command-and-control communication channel."
        persistence_assessment = (
            "Autostart registry persistence observed directly in behavioral telemetry."
            if has_pers else "No active autostart persistence observed in provided telemetry."
        )

        recs = [
            "Isolate the host system from the internal enterprise network segment.",
            "Inspect and remove identified dropped executable binaries and registry Run keys.",
            "Add identified C2 IP addresses and DNS domains to perimeter blocklists and SIEM detection rules."
        ]

        return Assessment(
            assessment_id="A-0001",
            title=f"Malware Triage Assessment: {classification}",
            threat_level=threat_level,
            threat_score=threat_score,
            classification=classification,
            summary=summary,
            key_functionality=key_func,
            purpose=purpose,
            persistence_assessment=persistence_assessment,
            runtime_confirmation_status="NOT_CONFIRMED" if has_inj else "OBSERVED",
            mitre_techniques=list(mitre_map.values()),
            host_iocs=sorted(list(host_iocs)),
            network_iocs=sorted(list(network_iocs)),
            recommendations=recs,
            supporting_finding_ids=supporting_fids
        )
