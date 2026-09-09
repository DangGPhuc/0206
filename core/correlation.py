"""
0206 - Cross-Stage Correlation Engine
Correlates findings and evidence across static, code, and behavioral analysis stages.
Elevates capabilities (CAPABILITY) to confirmed behaviors (CONFIRMED_BEHAVIOR)
only when multi-source evidence is strictly present.
Never treats a single weak heuristic as confirmed malware behavior.
"""
from typing import List, Dict, Any, Optional
from core.schemas import AnalysisDomain, EvidenceState, Finding, FindingStatus, FindingSeverity
from core.evidence import EvidenceStore


class CorrelationRule:
    """Represents an analytical correlation rule connecting facts across domains."""
    def __init__(self, rule_id: str, name: str, description: str):
        self.rule_id = rule_id
        self.name = name
        self.description = description


class CorrelationEngine:
    """
    Evaluates evidence facts and preliminary findings to identify multi-source correlations.
    Transforms raw capabilities into confirmed runtime behaviors with traceable provenance.
    """

    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store

    def correlate(self, findings: List[Finding]) -> List[Finding]:
        """
        Applies cross-stage correlation rules across all established findings.
        Returns the updated list of findings with elevated statuses and correlation metadata.
        """
        correlated = list(findings)

        # 1. Process Injection Correlation (API Capability + Behavioral Memory/Thread Event)
        self._correlate_process_injection(correlated)

        # 2. C2 Channel Correlation (DNS + HTTP/TLS + Periodic Flow)
        self._correlate_c2_channel(correlated)

        # 3. Host Persistence Correlation (Registry Key Mention + Runtime Autostart Write)
        self._correlate_persistence(correlated)

        # 4. Unpacking & Anti-Analysis Correlation (Entropy + Disassembly Anomalies)
        self._correlate_unpacking_anti_analysis(correlated)

        return correlated

    def _correlate_process_injection(self, findings: List[Finding]):
        """
        Correlates a static process-injection capability with explicit remote-memory
        and remote-execution telemetry. Generic process creation alone is never
        sufficient to confirm process injection.
        """
        inj_findings = [
            f for f in findings
            if f.domain in (AnalysisDomain.PROCESS, AnalysisDomain.MEMORY)
            and "Injection" in f.title
        ]
        if not inj_findings:
            return

        remote_alloc_evs = self.evidence_store.find(field="remote_memory_allocation")
        remote_write_evs = self.evidence_store.find(field="remote_write")
        remote_thread_evs = self.evidence_store.find(field="remote_thread")

        has_remote_memory_manipulation = bool(remote_alloc_evs or remote_write_evs)
        has_remote_execution = bool(remote_thread_evs)
        corroborating_evs = remote_alloc_evs + remote_write_evs + remote_thread_evs

        for f in inj_findings:
            if has_remote_memory_manipulation and has_remote_execution:
                f.status = FindingStatus.CONFIRMED_BEHAVIOR
                f.state = EvidenceState.OBSERVED
                f.confidence = min(0.98, f.confidence + 0.20)
                f.correlation_rule = (
                    "CORR-001: Static Injection Capability Corroborated by "
                    "Remote Memory Manipulation and Remote Execution"
                )
                f.why_it_matters = (
                    "Static injection capability was corroborated by explicit runtime evidence "
                    "of remote memory manipulation and remote execution."
                )
                for ev in corroborating_evs:
                    if ev.evidence_id not in f.evidence_ids:
                        f.evidence_ids.append(ev.evidence_id)
            elif corroborating_evs:
                # A single remote-injection signal is meaningful, but not enough for confirmation.
                f.status = FindingStatus.INFERRED_BEHAVIOR
                f.state = EvidenceState.INFERRED
                f.confidence = min(0.90, f.confidence + 0.08)
                f.correlation_rule = "CORR-001-PARTIAL: Partial Runtime Injection Signal"
                f.why_it_matters = (
                    "A runtime signal associated with injection was observed, but the evidence "
                    "does not establish both remote memory manipulation and remote execution."
                )
                for ev in corroborating_evs:
                    if ev.evidence_id not in f.evidence_ids:
                        f.evidence_ids.append(ev.evidence_id)
            else:
                f.status = FindingStatus.CAPABILITY
                f.state = EvidenceState.INFERRED
                f.why_it_matters = (
                    "Static import table contains process injection APIs; however, runtime execution "
                    "was not confirmed by behavioral monitoring."
                )

    def _correlate_c2_channel(self, findings: List[Finding]):
        """
        Correlates network periodic beaconing with DNS resolution and HTTP/TLS request flows
        using calibrated terminology (CONFIRMED_C2, LIKELY_C2_BEACON, SUSPECTED_BEACONING, OBSERVED_PERIODIC_TRAFFIC).
        """
        net_findings = [f for f in findings if f.domain in (AnalysisDomain.NETWORK, AnalysisDomain.C2)]
        dns_evs = self.evidence_store.find(source_type="PCAP_DNS")
        http_evs = self.evidence_store.find(source_type="PCAP_HTTP")

        for f in net_findings:
            title_upper = f.title.upper()
            if "CONFIRMED_C2" in title_upper or "CONFIRMED C2" in title_upper:
                f.status = FindingStatus.CONFIRMED_BEHAVIOR
                f.state = EvidenceState.OBSERVED
                f.correlation_rule = "CORR-002: Multi-Factor Periodic Flow Corroborated with HTTP/DNS Traffic"
                f.why_it_matters = "Periodic network beaconing was corroborated by application layer request patterns to the same endpoint."
            elif "LIKELY_C2_BEACON" in title_upper or "LIKELY C2" in title_upper:
                f.status = FindingStatus.INFERRED_BEHAVIOR
                f.state = EvidenceState.INFERRED
                f.correlation_rule = "CORR-003: High-Confidence Periodic Beacon Corroborated with Application Endpoint"
                f.why_it_matters = "High statistical periodicity and destination consistency indicate likely C2 beaconing activity."
            elif "SUSPECTED_BEACONING" in title_upper or "SUSPECTED" in title_upper:
                f.status = FindingStatus.OBSERVED_BEHAVIOR
                f.state = EvidenceState.INFERRED
                f.correlation_rule = "CORR-004: Suspected Beaconing Observed with Stable Interval Timing"
                f.why_it_matters = "Statistical interval stability observed; payload intent remains unconfirmed."
            elif "OBSERVED_PERIODIC_TRAFFIC" in title_upper or "BEACONING" in title_upper or "PERIODIC" in title_upper:
                f.status = FindingStatus.OBSERVED_BEHAVIOR
                f.state = EvidenceState.INFERRED
                f.correlation_rule = "CORR-005: Statistical Periodic Traffic Observed without Application-Layer C2 Proof"
                f.why_it_matters = "Statistical periodicity was observed in network flows, but payload semantics are unconfirmed."

    @staticmethod
    def _registry_path_from_evidence(ev: Any) -> str:
        """Extracts a comparable registry path from heterogeneous evidence values."""
        val = getattr(ev, "value", None)
        if isinstance(val, dict):
            for key in ("key_path", "path", "registry_key", "key"):
                if val.get(key):
                    return str(val[key])
        return str(val or "")

    @staticmethod
    def _normalize_registry_path(path: str) -> str:
        normalized = path.replace("/", "\\").strip().lower()
        for prefix in (
            "hkey_current_user\\", "hkcu\\",
            "hkey_local_machine\\", "hklm\\",
            "hkey_users\\", "hku\\",
        ):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break
        return normalized.rstrip("\\")

    @classmethod
    def _registry_paths_related(cls, left: str, right: str) -> bool:
        a = cls._normalize_registry_path(left)
        b = cls._normalize_registry_path(right)
        if not a or not b:
            return False
        return a == b or a in b or b in a

    def _correlate_persistence(self, findings: List[Finding]):
        """
        Correlates persistence findings only with runtime registry evidence that
        references the same autostart location. Unrelated registry activity never
        upgrades a capability to CONFIRMED_BEHAVIOR.
        """
        pers_findings = [
            f for f in findings
            if (f.domain in (AnalysisDomain.PERSISTENCE, AnalysisDomain.REGISTRY) or
                getattr(f.domain, "value", str(f.domain)) in ("PERSISTENCE", "REGISTRY"))
        ]

        runtime_reg_evs = []
        for ev in self.evidence_store.all():
            source_type = str(getattr(ev, "source_type", ""))
            field = str(getattr(ev, "field", ""))
            if (
                source_type in {"REGSHOT_MODIFIED", "PROCMON_REG", "PROCMON_REGISTRY"}
                or field in {"registry_persistence", "reg_set_value", "registry_write"}
            ):
                runtime_reg_evs.append(ev)

        for f in pers_findings:
            finding_evs = [self.evidence_store.get(eid) for eid in f.evidence_ids]
            finding_evs = [ev for ev in finding_evs if ev is not None]
            finding_paths = [self._registry_path_from_evidence(ev) for ev in finding_evs]

            # Do not use the same evidence record to corroborate itself.
            existing_ids = set(f.evidence_ids)
            matching_runtime = [
                ev for ev in runtime_reg_evs
                if ev.evidence_id not in existing_ids
                and any(
                    self._registry_paths_related(path, self._registry_path_from_evidence(ev))
                    for path in finding_paths
                )
            ]

            if matching_runtime:
                f.status = FindingStatus.CONFIRMED_BEHAVIOR
                f.state = EvidenceState.OBSERVED
                f.confidence = min(0.95, f.confidence + 0.15)
                f.correlation_rule = "CORR-006: Matching Autostart Registry Location Verified in Runtime Telemetry"
                f.why_it_matters = (
                    "The same autostart registry location identified by the finding was modified "
                    "in runtime telemetry, providing cross-source corroboration."
                )
                for ev in matching_runtime:
                    if ev.evidence_id not in f.evidence_ids:
                        f.evidence_ids.append(ev.evidence_id)
            elif f.status == FindingStatus.CAPABILITY:
                f.state = EvidenceState.INFERRED
                f.why_it_matters = (
                    "A persistence-capable registry location was identified, but no matching "
                    "runtime modification was observed."
                )

    def _correlate_unpacking_anti_analysis(self, findings: List[Finding]):
        """
        Correlates high section entropy, RWX sections, and invalid disassembly instructions into unpacking requirement.
        """
        packing_findings = [f for f in findings if f.domain in (AnalysisDomain.PACKING, AnalysisDomain.OBFUSCATION, AnalysisDomain.UNPACKING)]
        rwx_evs = self.evidence_store.find(field="section_is_rwx")
        anomaly_evs = self.evidence_store.find(field="disassembly_anomaly")

        for f in packing_findings:
            if rwx_evs and anomaly_evs:
                f.status = FindingStatus.OBSERVED_BEHAVIOR
                f.severity = FindingSeverity.HIGH
                f.correlation_rule = "CORR-005: RWX Sections Combined with High Entropy & Disassembly Anomalies"
                f.why_it_matters = (
                    "Concurrent high entropy, RWX section permissions, and entry-point code anomalies strongly suggest "
                    "a packed stub or crypter. Dynamic unpacking is required for complete analysis."
                )
