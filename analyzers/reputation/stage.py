"""
0206 - Reputation Pipeline Stage
Pluggable stage executing hash reputation queries between HASH and STATIC analysis.
Guarantees:
- HASH LOOKUP ONLY by default.
- Never automatically uploads sample binaries.
- Reputation failure never aborts analysis.
- Offline mode and missing API keys gracefully record NOT_CHECKED.
- NEVER equates NOT_FOUND with CLEAN.
- Normalizes output into canonical EvidenceRecord objects.
"""
from typing import Optional, Any
from datetime import datetime, timezone

from core.schemas import AnalysisDomain, EvidenceState
from core.evidence import EvidenceStore
from analyzers.reputation.provider import ReputationProvider, ReputationResult, ReputationStatus
from analyzers.reputation.virustotal import VirusTotalReputationProvider


class ReputationStage:
    """
    Pluggable Pipeline Stage for hash reputation lookup.
    """

    def __init__(
        self,
        provider: Optional[ReputationProvider] = None,
        offline: bool = False,
        api_key: Optional[str] = None
    ):
        self.offline = offline
        self.provider = provider or VirusTotalReputationProvider(api_key=api_key)

    def analyze(
        self,
        sample_sha256: str,
        evidence_store: Optional[EvidenceStore] = None,
        artifact_name: str = "sample"
    ) -> ReputationResult:
        """
        Executes hash reputation query and emits canonical EvidenceRecord objects.
        """
        clean_hash = (sample_sha256 or "").strip().lower()

        if self.offline:
            res = ReputationResult(
                provider="VirusTotal",
                query_hash=clean_hash,
                status=ReputationStatus.SKIPPED_OFFLINE,
                details="Offline mode active: external reputation API lookup disabled."
            )
        else:
            try:
                res = self.provider.lookup_hash(clean_hash, evidence_store=evidence_store)
            except Exception as e:
                res = ReputationResult(
                    provider="VirusTotal",
                    query_hash=clean_hash,
                    status=ReputationStatus.LOOKUP_FAILED,
                    details=f"Reputation lookup failed: {e}"
                )

        # Store reputation output as EvidenceRecord objects (Phase 2)
        if evidence_store is not None and clean_hash:
            status_str = res.status.value if hasattr(res.status, "value") else str(res.status)
            if status_str in ("NOT_CHECKED", "SKIPPED_OFFLINE", "LOOKUP_FAILED"):
                ratio_val = "N/A"
            elif status_str == "NOT_FOUND":
                ratio_val = "NOT_FOUND"
            elif res.total_engines > 0:
                ratio_val = f"{res.detection_count}/{res.total_engines}"
            else:
                ratio_val = "N/A"

            state = EvidenceState.OBSERVED if status_str in (
                "KNOWN_MALICIOUS", "KNOWN_SUSPICIOUS", "LOW_DETECTION"
            ) else (
                EvidenceState.NOT_AVAILABLE if status_str in ("LOOKUP_FAILED", "NOT_CHECKED", "SKIPPED_OFFLINE")
                else EvidenceState.INFERRED
            )

            evidence_store.create(
                source_artifact=artifact_name,
                source_type="REPUTATION",
                field="detection_ratio",
                value=ratio_val,
                extractor=res.provider,
                artifact_sha256=clean_hash,
                domain=AnalysisDomain.PE,
                state=state,
                confidence=0.95 if status_str in ("KNOWN_MALICIOUS", "KNOWN_SUSPICIOUS") else 0.5,
                provenance={
                    "queried_hash": res.query_hash,
                    "provider": res.provider,
                    "status": status_str,
                    "lookup_status": status_str,
                    "detection_count": res.detection_count,
                    "total_engines": res.total_engines,
                    "positives": res.detection_count,
                    "total": res.total_engines,
                    "malware_names": res.malware_names,
                    "first_seen": res.first_seen,
                    "last_analysis": res.last_analysis,
                    "provider_response_hash": res.raw_response_hash,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "details": res.details
                },
                prefix="E-REPUTATION"
            )

            evidence_store.create(
                source_artifact=artifact_name,
                source_type="REPUTATION",
                field="lookup_status",
                value=status_str,
                extractor=res.provider,
                artifact_sha256=clean_hash,
                domain=AnalysisDomain.PE,
                state=state,
                confidence=1.0,
                provenance={
                    "queried_hash": res.query_hash,
                    "provider": res.provider,
                    "status": status_str,
                    "lookup_status": status_str,
                    "positives": res.detection_count,
                    "total": res.total_engines,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                },
                prefix="E-REPUTATION"
            )

        return res

    def execute(
        self,
        sample_sha256: str,
        evidence_store: Optional[EvidenceStore] = None,
        offline: Optional[bool] = None,
        artifact_name: str = "sample"
    ):
        """Convenience method executing stage and returning created EvidenceRecords."""
        if offline is not None:
            self.offline = offline
        store = evidence_store if evidence_store is not None else EvidenceStore()
        self.analyze(sample_sha256, evidence_store=store, artifact_name=artifact_name)
        return store.find(source_type="REPUTATION")


# Alias for architectural naming consistency
ReputationAnalyzer = ReputationStage
