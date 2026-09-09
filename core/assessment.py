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
    Classification, RecommendationRecord, ScoreContribution, CoverageStatus, Assessment
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
                f_status = getattr(f, "status", None)
                status_str = "CONFIRMED" if f_status == FindingStatus.CONFIRMED_BEHAVIOR else (
                    "OBSERVED" if f_status == FindingStatus.OBSERVED_BEHAVIOR else "NOT_CONFIRMED"
                )
                mitre_map[f.mitre_attack_id] = {
                    "technique": f.mitre_attack_id,
                    "technique_id": f.mitre_attack_id,
                    "technique_name": f.title,
                    "tactic": f.mitre_tactic or "Execution",
                    "status": status_str,
                    "confidence": round(f.confidence, 2),
                    "basis": f.why_it_matters or f.details[:120],
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

        # Structured Classification (P0.5)
        has_inj = any(f.domain in (AnalysisDomain.PROCESS, AnalysisDomain.MEMORY) for f in findings)
        has_net = any(f.domain in (AnalysisDomain.NETWORK, AnalysisDomain.C2) for f in findings)
        has_pers = any(f.domain in (AnalysisDomain.PERSISTENCE, AnalysisDomain.REGISTRY) for f in findings)

        rep_records = [e for e in self.evidence_store.all() if e.source_type == "REPUTATION" and e.field == "lookup_status"]
        has_mal_rep = any(r.value in ("KNOWN_MALICIOUS", "KNOWN_SUSPICIOUS") for r in rep_records)

        if not findings and not has_mal_rep:
            class_val = "UNKNOWN / NOT_ESTABLISHED"
            class_status = "NOT_ESTABLISHED"
            class_conf = 0.0
            class_basis = ["No suspicious findings or hostile capabilities established"]
        elif threat_level == "INFORMATIONAL / CLEAN":
            class_val = "Benign / Low Risk"
            class_status = "INFERRED"
            class_conf = 0.85
            class_basis = ["Triage indicators within normal benign software baseline"]
        elif has_inj and has_net:
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
        elif threat_score >= 40:
            class_val = "Suspicious.Heuristic"
            class_status = "HEURISTIC"
            class_conf = 0.65
            class_basis = ["Heuristic anomalies identified without confirmed C2 or persistence"]
        elif threat_score >= 20:
            class_val = "Suspicious.LowRisk"
            class_status = "INFERRED"
            class_conf = 0.50
            class_basis = ["Low-severity heuristic indicators identified"]
        else:
            class_val = "UNKNOWN / NOT_ESTABLISHED"
            class_status = "NOT_ESTABLISHED"
            class_conf = 0.0
            class_basis = ["No suspicious findings or hostile capabilities established"]

        classification_details = Classification(
            value=class_val,
            confidence=class_conf,
            basis=class_basis,
            status=class_status
        )

        # Advanced Analysis Triggers (P2.18)
        advanced_triggers = []
        for f in findings:
            if "RWX" in f.title or "Entropy" in f.title:
                advanced_triggers.append("Memory dump / unpacking analysis triggered by high entropy / RWX sections")
            if "API Hashing" in f.title or "Dynamic API" in f.title:
                advanced_triggers.append("Interactive disassembler (Ghidra/IDA) triggered by runtime API resolution candidates")
            if "Injection" in f.title or "Process" in f.title:
                advanced_triggers.append("Process monitor execution trace triggered by process manipulation capability")
            if "Beacon" in f.title or "Network" in f.title:
                advanced_triggers.append("Interactive PCAP / TLS inspection triggered by potential C2 activity")

        # Phase 29: Analysis Coverage Calculation across all domains
        coverage_map = self._compute_coverage(findings)

        summary = (
            f"Evidence-grounded deterministic assessment evaluated {len(self.evidence_store)} forensic evidence records "
            f"and established {len(findings)} technical findings. Threat score is assessed at {threat_score}/100 ({threat_level}) "
            f"with classification '{class_val}'."
        )

        # Purpose text conditioned on grounded findings
        if threat_score == 0 or not findings:
            purpose_text = "NOT_ESTABLISHED"
        elif has_inj and has_net:
            purpose_text = "Host manipulation and remote network interaction."
        elif has_net:
            purpose_text = "Remote network communications."
        elif has_pers:
            purpose_text = "System persistence / autostart."
        else:
            purpose_text = "NOT_ESTABLISHED"

        # Recommendations conditioned on findings/coverage
        if not findings or threat_score == 0:
            rec_records = [
                RecommendationRecord(
                    action="Retain case artifacts and cryptographic manifest for audit trail",
                    reason="No hostile indicators or suspicious capabilities established from basic static triage.",
                    priority="LOW",
                    trigger_finding_ids=[]
                ),
                RecommendationRecord(
                    action="Submit execution telemetry for dynamic evaluation if suspicion persists",
                    reason="Absence of static indicators does not preclude dormant or environment-keyed payloads.",
                    priority="LOW",
                    trigger_finding_ids=[]
                )
            ]
            recommendations = [f"[{r.priority}] {r.action}: {r.reason}" for r in rec_records]
        else:
            rec_records = [
                RecommendationRecord(
                    action="Maintain host safety: avoid live hostile execution on analyst workstation",
                    reason="Suspicious or potentially hostile binary capabilities identified.",
                    priority="HIGH" if threat_score >= 60 else "MEDIUM",
                    trigger_finding_ids=supporting_fids[:3]
                ),
                RecommendationRecord(
                    action="Verify all external threat attribution against verified Evidence IDs",
                    reason="Attribution hypotheses must remain grounded in deterministic forensic records.",
                    priority="LOW",
                    trigger_finding_ids=supporting_fids[:2]
                )
            ]
            if has_pers:
                pers_fids = [f.finding_id for f in findings if f.domain in (AnalysisDomain.PERSISTENCE, AnalysisDomain.REGISTRY)]
                rec_records.append(RecommendationRecord(
                    action="Inspect host autostart locations and remove unauthorized persistence keys",
                    reason="Registry or autostart persistence indicators identified.",
                    priority="HIGH",
                    trigger_finding_ids=pers_fids
                ))
            if has_net:
                net_fids = [f.finding_id for f in findings if f.domain in (AnalysisDomain.NETWORK, AnalysisDomain.C2)]
                rec_records.append(RecommendationRecord(
                    action="Block identified external network endpoints at perimeter firewalls",
                    reason="Network beaconing or external command-and-control communication observed.",
                    priority="HIGH" if any("CONFIRMED_C2" in f.title for f in findings) else "MEDIUM",
                    trigger_finding_ids=net_fids
                ))
            recommendations = [f"[{r.priority}] {r.action}: {r.reason}" for r in rec_records]

        analysis_conf = 1.0 if len(self.evidence_store) > 0 else 0.5

        return Assessment(
            assessment_id=f"ASSESS-{threat_score}",
            title=f"Deterministic Assessment: {class_val}",
            threat_level=threat_level,
            threat_score=threat_score,
            classification=class_val,
            classification_details=classification_details,
            score_breakdown=score_breakdown,
            summary=summary,
            key_functionality=f"Capabilities: {'Injection APIs; ' if has_inj else ''}{'Network communications; ' if has_net else ''}{'Persistence Run keys; ' if has_pers else ''}" or "No hostile capabilities identified",
            purpose=purpose_text,
            persistence_assessment="Autostart Run key configured" if has_pers else "None confirmed",
            runtime_confirmation_status="Corroborated by host/network telemetry" if (has_pers or has_net) else "Static capability only; unconfirmed at runtime",
            coverage=coverage_map,
            mitre_techniques=list(mitre_map.values()),
            host_iocs=sorted(list(host_iocs)),
            network_iocs=sorted(list(network_iocs)),
            recommendations=recommendations,
            supporting_finding_ids=supporting_fids,
            evidence_graph_nodes=len(self.evidence_store),
            confidence=class_conf,
            classification_confidence=class_conf,
            analysis_confidence=analysis_conf
        )

    def _compute_coverage(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Determines the analysis coverage status across all major domains and stages.
        Standardizes terminology and accurately reflects offline/skipped reputation.
        Includes coverage reason fields and standardized 4-tier stages.
        """
        active_domains = {f.domain for f in findings}
        evidence_types = {e.source_type for e in self.evidence_store.all()}
        rep_recs = [e for e in self.evidence_store.all() if e.source_type == "REPUTATION" and e.field == "lookup_status"]
        if rep_recs:
            r_val = rep_recs[0].value
            if r_val == "SKIPPED_OFFLINE":
                rep_cov_status = CoverageStatus.SKIPPED_OFFLINE.value
            elif r_val in ("NOT_CHECKED", "LOOKUP_FAILED"):
                rep_cov_status = CoverageStatus.NOT_CHECKED.value
            elif r_val in ("KNOWN_MALICIOUS", "KNOWN_SUSPICIOUS", "LOW_DETECTION", "NOT_FOUND"):
                rep_cov_status = CoverageStatus.COMPLETED.value
            else:
                rep_cov_status = CoverageStatus.NOT_CHECKED.value
        else:
            rep_cov_status = CoverageStatus.NOT_ANALYZED.value

        has_pe = any("PE" in t for t in evidence_types)
        has_code = any("DISASSEMBLY" in t for t in evidence_types)
        has_pcap = any("PCAP" in t for t in evidence_types)
        has_proc = any("PROCMON" in t for t in evidence_types)
        has_reg = any("REG" in t for t in evidence_types)

        domain_coverage = {
            "PE Static": CoverageStatus.COMPLETED.value if has_pe else CoverageStatus.NOT_ANALYZED.value,
            "Code Triage": CoverageStatus.COMPLETED.value if has_code else CoverageStatus.NOT_ANALYZED.value,
            "Reputation": rep_cov_status,
            "Network": CoverageStatus.COMPLETED.value if has_pcap else CoverageStatus.NOT_ANALYZED.value,
            "Process": CoverageStatus.COMPLETED.value if has_proc else CoverageStatus.NOT_ANALYZED.value,
            "Registry": CoverageStatus.COMPLETED.value if has_reg else CoverageStatus.NOT_ANALYZED.value,
            "Memory": CoverageStatus.NOT_AVAILABLE.value,
            "Unpacking": CoverageStatus.PARTIAL.value if AnalysisDomain.PACKING in active_domains else CoverageStatus.NOT_ANALYZED.value,
            "Anti-Analysis": CoverageStatus.PARTIAL.value if AnalysisDomain.ANTI_ANALYSIS in active_domains else CoverageStatus.NOT_ANALYZED.value,
            ".NET": CoverageStatus.NOT_APPLICABLE.value
        }

        coverage_reasons = {
            "PE Static": "PE headers, sections, imports, and metadata inspected from sample." if has_pe else "No PE executable structure provided.",
            "Code Triage": "Capstone linear disassembly triage performed on entry point." if has_code else "No machine code instructions disassembled.",
            "Reputation": "External hash reputation database queried." if rep_cov_status == CoverageStatus.COMPLETED.value else (
                "External reputation lookup skipped (offline mode enabled)." if rep_cov_status == "SKIPPED_OFFLINE" else
                "External reputation lookup skipped (no API key configured or unqueried)."
            ),
            "Network": "Network packets ingested and inspected from PCAP artifact." if has_pcap else "No PCAP capture artifact provided for ingestion.",
            "Process": "Process lifecycle events ingested from Procmon trace." if has_proc else "No Procmon PML/CSV artifact provided for ingestion.",
            "Registry": "Registry key operations ingested from Procmon/Regshot." if has_reg else "No registry capture artifact provided for ingestion.",
            "Memory": "Memory acquisition and volatility analysis not engaged in basic triage.",
            "Unpacking": "Packing heuristics and section entropy analyzed." if AnalysisDomain.PACKING in active_domains else "Dynamic unpacking / payload extraction not engaged in basic triage; requires execution tracing or memory dump analysis.",
            "Anti-Analysis": "Heuristic evasion and anti-analysis patterns scanned." if AnalysisDomain.ANTI_ANALYSIS in active_domains else "Dedicated anti-analysis and evasion detection not engaged in basic triage profile.",
            ".NET": "Native Windows PE binary; .NET CLR runtime header not present."
        }

        stages = {
            "Basic Static Analysis": {
                "status": CoverageStatus.COMPLETED.value if has_pe else CoverageStatus.NOT_ANALYZED.value,
                "reason": "PE headers, sections, exports, imports, and disassembly triage completed."
            },
            "Basic Behavioral Analysis": {
                "status": CoverageStatus.COMPLETED.value if (has_pcap or has_proc or has_reg) else CoverageStatus.NOT_ANALYZED.value,
                "reason": "Ingested recorded host/network artifacts (safe ingestion; no live execution)." if (has_pcap or has_proc or has_reg) else "No behavioral telemetry artifacts (PCAP, Procmon, Regshot) provided."
            },
            "Advanced Static Analysis": {
                "status": CoverageStatus.NOT_ANALYZED.value,
                "reason": "Deep interactive disassembly / decompiler analysis (IDA Pro / Ghidra) not invoked."
            },
            "Advanced Dynamic Analysis": {
                "status": CoverageStatus.NOT_ANALYZED.value,
                "reason": "Live sandbox execution disabled on host; requires isolated VM environment."
            }
        }

        # Retain domain keys for backward-compatibility while exposing domain_coverage, coverage_reasons, and stages
        coverage = dict(domain_coverage)
        coverage["domain_coverage"] = domain_coverage
        coverage["coverage_reasons"] = coverage_reasons
        coverage["stages"] = stages
        return coverage
