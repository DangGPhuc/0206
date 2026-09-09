"""
0206 - Offline Deterministic AI Provider
Phase 17: Default fallback provider that operates completely offline with zero network calls.
"""
from typing import Dict, Any, List, Optional
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
        request: Optional[Any] = None,
        evidence_store: Optional[EvidenceStore] = None,
        findings: Optional[List[Finding]] = None,
        system_prompt: Optional[str] = None,
        user_prompt: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        req_findings = getattr(request, "findings", None) if request else None
        target_findings = findings or []

        # If findings were passed inside SanitizedAIRequest as dicts
        if not target_findings and req_findings:
            high_findings = [f for f in req_findings if f.get("confidence", 0) >= 0.7]
            hypotheses = []
            for h in high_findings[:5]:
                hypotheses.append({
                    "claim": f"High confidence indicator: {h.get('title', '')}",
                    "confidence": h.get("confidence", 0.0),
                    "supported_by_evidence_ids": h.get("evidence_ids", []),
                    "domain": str(h.get("domain", "")),
                    "why_it_matters": h.get("why_it_matters", ""),
                })
            narrative = (
                f"Deterministic analysis completed across {len(req_findings)} correlated findings. "
                f"Identified {len(high_findings)} prominent indicators of interest."
            )
            return {
                "executive_summary": narrative,
                "hypotheses": hypotheses,
                "behavioral_claims": [],
                "mitre_attack_mappings": [
                    {"technique_id": f.get("mitre_attack_id"), "evidence_id": f.get("evidence_ids", [""])[0]}
                    for f in req_findings if f.get("mitre_attack_id") and f.get("evidence_ids")
                ],
                "limitations_identified": [
                    "Offline deterministic analysis mode utilized; no external LLM heuristics invoked.",
                    "Observations restricted to supplied static and dynamic evidence artifacts."
                ]
            }

        high_findings_objs = [f for f in target_findings if f.confidence >= 0.7]
        hypotheses = []
        for h in high_findings_objs[:5]:
            hypotheses.append({
                "claim": f"High confidence indicator: {h.title}",
                "confidence": h.confidence,
                "supported_by_evidence_ids": h.evidence_ids,
                "domain": h.domain.value if hasattr(h.domain, "value") else str(h.domain),
                "why_it_matters": h.why_it_matters or h.details,
            })

        narrative = (
            f"Deterministic analysis completed across {len(target_findings)} correlated findings. "
            f"Identified {len(high_findings_objs)} prominent indicators of interest."
        )

        return {
            "executive_summary": narrative,
            "hypotheses": hypotheses,
            "behavioral_claims": [],
            "mitre_attack_mappings": [
                {"technique_id": f.mitre_attack_id, "evidence_id": f.evidence_ids[0]}
                for f in target_findings if f.mitre_attack_id and f.evidence_ids
            ],
            "limitations_identified": [
                "Offline deterministic analysis mode utilized; no external LLM heuristics invoked.",
                "Observations restricted to supplied static and dynamic evidence artifacts."
            ]
        }
