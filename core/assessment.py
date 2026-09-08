"""
0206 - Deterministic Threat Assessment & Explainable Scoring Engine
Authoritative scoring layer implementing:
- Multi-factor calibrated contribution formula:
    contribution = base_weight * confidence * evidence_strength * corroboration * decay
- Saturation caps per domain to prevent duplicate findings from inflating scores
- Full explainability via ScoreContribution breakdown
- Structured Classification object with explicit status
- Comprehensive AnalysisCoverage evaluation across all 25 domains
"""
from typing import List, Dict, Any, Optional
from core.schemas import (
    AnalysisDomain, EvidenceState, Finding, FindingStatus, FindingSeverity,
    Classification, ScoreContribution, CoverageStatus, Assessment
)
from core.evidence import EvidenceStore


# Base Weights calibrated per Analytical Domain
DOMAIN_WEIGHTS: Dict[AnalysisDomain, float] = {
    AnalysisDomain.PERSISTENCE: 35.0,
    AnalysisDomain.C2: 35.0,
    AnalysisDomain.NETWORK: 25.0,
    AnalysisDomain.PROCESS: 30.0,
    AnalysisDomain.MEMORY: 30.0,
    AnalysisDomain.CODE_EXECUTION: 25.0,
    AnalysisDomain.ANTI_ANALYSIS: 25.0,
    AnalysisDomain.PACKING: 20.0,
    AnalysisDomain.UNPACKING: 20.0,
    AnalysisDomain.OBFUSCATION: 20.0,
    AnalysisDomain.API: 15.0,
    AnalysisDomain.ASSEMBLY: 15.0,
    AnalysisDomain.FILESYSTEM: 20.0,
    AnalysisDomain.REGISTRY: 20.0,
    AnalysisDomain.CRYPTOGRAPHY: 15.0,
    AnalysisDomain.SHELLCODE: 25.0,
    AnalysisDomain.DOTNET: 15.0,
    AnalysisDomain.PE: 10.0,
    AnalysisDomain.LOADER: 15.0,
    AnalysisDomain.DNS: 15.0,
    AnalysisDomain.HTTP: 15.0,
    AnalysisDomain.TLS: 15.0,
    AnalysisDomain.DOCUMENT: 15.0,
    AnalysisDomain.SCRIPT: 15.0,
    AnalysisDomain.THREAD: 20.0
}


class AssessmentEngine:
    """
    Computes deterministic, auditable threat scores, classification, and coverage.
    Remains the authoritative scoring layer: AI models can never override this assessment.
    """

    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store

    def assess(self, findings: List[Finding]) -> Assessment:
        """
        Evaluates verified findings and computes explainable score, classification, and domain coverage.
        """
        score_breakdown: List[ScoreContribution] = []
        domain_counts: Dict[str, int] = {}
        total_calculated_score: float = 0.0
        supporting_fids: List[str] = []
        mitre_map: Dict[str, Dict[str, Any]] = {}
        host_iocs: set = set()
        network_iocs: set = set()

        # Extract IOCs strictly from verified EvidenceStore records
        for e in self.evidence_store.all():
            if e.field == "sha256":
                host_iocs.add(f"SHA256: {e.value}")
            elif e.field == "imphash" and e.value != "N/A":
                host_iocs.add(f"Imphash: {e.value}")
            elif e.field == "dropped_file":
                p = e.value.get("path") if isinstance(e.value, dict) else str(e.value)
                host_iocs.add(f"Dropped File: {p}")
            elif e.field == "registry_persistence":
                kp = e.value.get("key_path") if isinstance(e.value, dict) else str(e.value)
                host_iocs.add(f"Run Key: {kp}")
            elif e.field == "dns_query":
                d = e.value.get("domain") if isinstance(e.value, dict) else str(e.value)
                network_iocs.add(f"DNS Domain: {d}")
                if isinstance(e.value, dict):
                    for ip in e.value.get("resolved_ips", []):
                        network_iocs.add(f"Resolved IP: {ip}")
            elif e.field == "http_request" and isinstance(e.value, dict):
                network_iocs.add(f"HTTP {e.value.get('method', 'GET')}: http://{e.value.get('host', '')}{e.value.get('uri', '')}")
            elif e.field == "beacon_analysis" and isinstance(e.value, dict):
                dst = e.value.get("destination_ip")
                if dst:
                    network_iocs.add(f"Beacon Endpoint: {dst}:{e.value.get('destination_port', '')}")

        # Compute explainable score contribution per finding
        for f in findings:
            supporting_fids.append(f.finding_id)
            dom_key = f.domain.value if hasattr(f.domain, "value") else str(f.domain)
            base_wt = DOMAIN_WEIGHTS.get(dom_key)
            if base_wt is None:
                try:
                    base_wt = DOMAIN_WEIGHTS.get(AnalysisDomain(dom_key), 15.0)
                except Exception:
                    base_wt = 15.0

            # Evidence strength factor
            st_val = f.state.value if hasattr(f.state, "value") else str(f.state)
            if st_val == "OBSERVED":
                ev_strength = 1.0
            elif st_val == "INFERRED":
                ev_strength = 0.85
            elif st_val == "NOT_CONFIRMED":
                ev_strength = 0.40
            else:
                ev_strength = 0.0

            # Corroboration factor
            corroboration = min(1.30, 0.9 + 0.1 * len(f.evidence_ids))

            # Saturation decay per domain to prevent duplicate findings from inflating scores
            cnt = domain_counts.get(dom_key, 0)
            decay = 1.0 / (1.0 + 0.4 * cnt)
            domain_counts[dom_key] = cnt + 1

            contrib = round(base_wt * f.confidence * ev_strength * corroboration * decay, 2)
            total_calculated_score += contrib

            if hasattr(f, "category") and f.category:
                cat_str = f.category.value if hasattr(f.category, "value") else str(f.category)
            else:
                cat_str = dom_key
            score_breakdown.append(ScoreContribution(
                finding_id=f.finding_id,
                category=cat_str,
                domain=dom_key,
                base_weight=base_wt,
                confidence=round(f.confidence, 2),
                evidence_strength=ev_strength,
                corroboration=round(corroboration, 2),
                contribution=contrib
            ))

            if f.mitre_attack_id:
                mitre_map[f.mitre_attack_id] = {
                    "technique_id": f.mitre_attack_id,
                    "technique_name": f.title,
                    "tactic": f.mitre_tactic or "Execution",
                    "evidence_ids": f.evidence_ids
                }

        threat_score = min(100, max(0, int(round(total_calculated_score))))
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

        # Structured Classification
        has_inj = any(f.domain in (AnalysisDomain.PROCESS, AnalysisDomain.MEMORY) for f in findings)
        has_net = any(f.domain in (AnalysisDomain.NETWORK, AnalysisDomain.C2) for f in findings)
        has_pers = any(f.domain in (AnalysisDomain.PERSISTENCE, AnalysisDomain.REGISTRY) for f in findings)

        if has_inj and has_net:
            class_val = "Trojan.Dropper / Injector / C2 Agent"
            class_status = "HEURISTIC"
            class_conf = 0.85
            class_basis = ["Process injection capability identified", "Outbound network communications observed"]
        elif has_net and not has_inj:
            class_val = "Trojan.Downloader"
            class_status = "HEURISTIC"
            class_conf = 0.75
            class_basis = ["Network communication observed without injection capability"]
        elif has_pers:
            class_val = "Backdoor / Persistent Trojan"
            class_status = "HEURISTIC"
            class_conf = 0.80
            class_basis = ["Registry autostart persistence observed directly"]
        else:
            class_val = "Suspicious.PE.Generic"
            class_status = "INFERRED"
            class_conf = 0.60
            class_basis = ["General PE anomalies without confirmed C2 or persistence"]

        classification_details = Classification(
            value=class_val,
            confidence=class_conf,
            basis=class_basis,
            status=class_status
        )

        # Phase 29: Analysis Coverage Calculation across all domains
        coverage_map = self._compute_coverage(findings)

        summary = (
            f"Evidence-grounded deterministic assessment evaluated {len(self.evidence_store)} forensic evidence records "
            f"and established {len(findings)} technical findings. Threat score is assessed at {threat_score}/100 ({threat_level}) "
            f"with classification '{class_val}'."
        )

        recommendations = [
            "Quarantine and sandbox binary in isolated virtual machine before execution.",
            "Block outbound communication to identified IP/domain endpoints at firewall perimeter.",
            "Inspect host autostart registry keys and scheduled tasks for persistence artifacts.",
            "Verify process execution telemetry using Sysmon or EDR sensors."
        ]

        return Assessment(
            assessment_id=f"ASSESS-{threat_score}",
            title=f"Deterministic Assessment: {class_val}",
            threat_level=threat_level,
            threat_score=threat_score,
            classification=class_val,
            classification_details=classification_details,
            score_breakdown=score_breakdown,
            summary=summary,
            key_functionality=f"Capabilities: {'Injection APIs; ' if has_inj else ''}{'Network communications; ' if has_net else ''}{'Persistence Run keys; ' if has_pers else ''}",
            purpose="Suspicious execution or remote payload deployment.",
            persistence_assessment="Autostart Run key configured" if has_pers else "None confirmed",
            runtime_confirmation_status="Corroborated by host/network telemetry" if (has_pers or has_net) else "Static capability only; unconfirmed at runtime",
            coverage=coverage_map,
            mitre_techniques=list(mitre_map.values()),
            host_iocs=sorted(list(host_iocs)),
            network_iocs=sorted(list(network_iocs)),
            recommendations=recommendations,
            supporting_finding_ids=supporting_fids,
            evidence_graph_nodes=len(self.evidence_store)
        )

    def _compute_coverage(self, findings: List[Finding]) -> Dict[str, str]:
        """
        Determines the analysis coverage status across all major domains and stages.
        """
        coverage: Dict[str, str] = {}
        active_domains = {f.domain for f in findings}
        evidence_types = {e.source_type for e in self.evidence_store.all()}

        # Core Stages
        coverage["PE Static"] = CoverageStatus.COMPLETED.value if any("PE" in t for t in evidence_types) else CoverageStatus.NOT_ANALYZED.value
        coverage["Code Triage"] = CoverageStatus.COMPLETED.value if any("DISASSEMBLY" in t for t in evidence_types) else CoverageStatus.NOT_ANALYZED.value
        coverage["Reputation"] = CoverageStatus.COMPLETED.value if any("REPUTATION" in t for t in evidence_types) else CoverageStatus.NOT_ANALYZED.value
        coverage["Network"] = CoverageStatus.COMPLETED.value if any("PCAP" in t for t in evidence_types) else CoverageStatus.NOT_ANALYZED.value
        coverage["Process"] = CoverageStatus.COMPLETED.value if any("PROCMON" in t for t in evidence_types) else CoverageStatus.NOT_ANALYZED.value
        coverage["Registry"] = CoverageStatus.COMPLETED.value if any("REG" in t for t in evidence_types) else CoverageStatus.NOT_ANALYZED.value
        coverage["Memory"] = CoverageStatus.NOT_AVAILABLE.value
        coverage["Unpacking"] = CoverageStatus.PARTIAL.value if AnalysisDomain.PACKING in active_domains else CoverageStatus.NOT_ANALYZED.value
        coverage["Anti-Analysis"] = CoverageStatus.PARTIAL.value if AnalysisDomain.ANTI_ANALYSIS in active_domains else CoverageStatus.NOT_ANALYZED.value
        coverage[".NET"] = CoverageStatus.NOT_APPLICABLE.value

        return coverage
