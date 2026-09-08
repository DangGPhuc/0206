"""
0206 - Offline Deterministic AI Provider
Phase 17: Default fallback provider that operates completely offline with zero network calls.
"""
from typing import Dict, Any, List
from core.evidence import EvidenceStore
from core.findings import Finding
from ai.providers.base import AIProvider


class OfflineAIProvider(AIProvider):
    """Generates structured narrative summaries deterministically from existing findings."""

    @property
    def name(self) -> str:
        return "offline"

    def is_available(self) -> bool:
        return True

    def synthesize(
        self,
        evidence_store: EvidenceStore,
        findings: List[Finding],
        system_prompt: str,
        user_prompt: str,
    ) -> Dict[str, Any]:
        high_findings = [f for f in findings if f.confidence >= 0.7]
        hypotheses = []
        for h in high_findings[:5]:
            hypotheses.append({
                "claim": f"High confidence indicator: {h.title}",
                "confidence": h.confidence,
                "supported_by_evidence_ids": h.evidence_ids,
                "domain": h.domain.value if hasattr(h.domain, "value") else str(h.domain),
                "why_it_matters": h.why_it_matters or h.details,
            })

        narrative = (
            f"Deterministic analysis completed across {len(findings)} correlated findings. "
            f"Identified {len(high_findings)} prominent indicators of interest."
        )

        return {
            "executive_summary": narrative,
            "hypotheses": hypotheses,
            "behavioral_claims": [],
            "mitre_attack_mappings": [
                {"technique_id": f.mitre_attack_id, "evidence_id": f.evidence_ids[0]}
                for f in findings if f.mitre_attack_id and f.evidence_ids
            ],
            "limitations_identified": [
                "Offline deterministic analysis mode utilized; no external LLM heuristics invoked.",
                "Observations restricted to supplied static and dynamic evidence artifacts."
            ]
        }
