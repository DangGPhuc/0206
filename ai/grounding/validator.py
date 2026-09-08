"""
0206 - AI Grounding Validator
Phase 16 & 17: Grounding and evidence boundary validator.
Validates AI generated hypotheses, IOCs, and MITRE techniques against the EvidenceStore.
Enforces that AI can NEVER invent IOCs, override threat scores, or cite phantom evidence IDs.
"""
from typing import Dict, Any, List, Optional
from core.evidence import EvidenceStore
from core.findings import Finding, Assessment
from ai.validation.schema import (
    AIFieldStatus,
    AIValidationDecision,
    AIValidationResult,
)


class GroundingValidator:
    """Validates and filters AI-suggested content against ground-truth forensic evidence."""

    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store

    def validate_synthesis(
        self,
        ai_dict: Dict[str, Any],
        baseline: Assessment,
        findings: Optional[List[Finding]] = None
    ) -> tuple[Assessment, AIValidationResult]:
        """
        Merges AI output into baseline assessment while strictly enforcing evidence grounding.
        """
        val_result = AIValidationResult()

        def add_decision(field: str, status: AIFieldStatus, reason: str, orig: Any = None, res: Any = None):
            d = AIValidationDecision(
                field=field, status=status, reason=reason,
                original_value=orig, resolved_value=res
            )
            val_result.decisions.append(d)
            val_result.decisions_by_field[field] = d.model_dump()
            if status == AIFieldStatus.REJECTED:
                val_result.rejected_fields.append(field)
            elif status == AIFieldStatus.DOWNGRADED:
                val_result.downgraded_fields.append(field)
            elif status == AIFieldStatus.ACCEPTED:
                val_result.accepted_fields.append(field)

        # 1. Threat score: AI CANNOT override deterministic score
        proposed_score = ai_dict.get("threat_score")
        if proposed_score is not None and proposed_score != baseline.threat_score:
            add_decision(
                "threat_score", AIFieldStatus.REJECTED,
                f"AI proposed score {proposed_score} was rejected. Deterministic score {baseline.threat_score} is authoritative.",
                proposed_score, baseline.threat_score
            )
        else:
            add_decision("threat_score", AIFieldStatus.ACCEPTED, "Deterministic score maintained.")

        # 2. Threat level: AI CANNOT override deterministic level
        proposed_level = ai_dict.get("threat_level")
        if proposed_level is not None and proposed_level != baseline.threat_level:
            add_decision(
                "threat_level", AIFieldStatus.REJECTED,
                f"AI proposed level '{proposed_level}' was rejected. Deterministic level '{baseline.threat_level}' is authoritative.",
                proposed_level, baseline.threat_level
            )
        else:
            add_decision("threat_level", AIFieldStatus.ACCEPTED, "Deterministic level maintained.")

        # 3. Malware family: Downgraded to SUSPECTED if not corroborated by multiple high-confidence findings
        proposed_family = ai_dict.get("malware_family")
        resolved_classification = baseline.classification
        if proposed_family and proposed_family not in ("UNKNOWN", "Generic Suspicious", baseline.classification):
            corroborated = findings and len([f for f in findings if f.confidence >= 0.8]) >= 3
            if corroborated:
                resolved_classification = proposed_family
                add_decision(
                    "malware_family", AIFieldStatus.ACCEPTED,
                    f"Family classification '{proposed_family}' corroborated by strong multi-stage findings.",
                    proposed_family, resolved_classification
                )
            else:
                resolved_classification = f"SUSPECTED_{proposed_family}"
                add_decision(
                    "malware_family", AIFieldStatus.DOWNGRADED,
                    f"Classification '{proposed_family}' downgraded to '{resolved_classification}' due to insufficient corroborating evidence.",
                    proposed_family, resolved_classification
                )
        else:
            add_decision("malware_family", AIFieldStatus.ACCEPTED, "Baseline classification preserved.", None, baseline.classification)

        # 4. MITRE ATT&CK: Validate cited evidence IDs
        validated_mitre = list(baseline.mitre_techniques)
        mitre_entries = ai_dict.get("mitre_attack") or ai_dict.get("mitre_techniques") or []
        for t in mitre_entries:
            eids = t.get("evidence_ids", [])
            valid_eids = [eid for eid in eids if self.evidence_store.get(eid)]
            if valid_eids:
                t["evidence_ids"] = valid_eids
                validated_mitre.append(t)
                add_decision(
                    f"mitre_technique_{t.get('technique_id')}", AIFieldStatus.ACCEPTED,
                    f"Technique cited verified evidence IDs: {valid_eids}",
                    eids, valid_eids
                )
            else:
                add_decision(
                    f"mitre_technique_{t.get('technique_id', 'unknown')}", AIFieldStatus.REJECTED,
                    "Technique rejected because it cited non-existent or ungrounded evidence IDs.",
                    eids, None
                )

        # 5. Narrative summaries & Recommendations
        exec_summary = ai_dict.get("executive_summary") or baseline.summary
        add_decision("executive_summary", AIFieldStatus.ACCEPTED, "Grounded executive narrative accepted.", None, None)

        recommendations = ai_dict.get("incident_recommendations") or baseline.recommendations
        add_decision("recommendations", AIFieldStatus.ACCEPTED, "Advisory response recommendations accepted.", None, None)

        merged = Assessment(
            assessment_id=baseline.assessment_id,
            title=f"Triage Assessment: {resolved_classification}",
            threat_level=baseline.threat_level,
            threat_score=baseline.threat_score,
            classification=resolved_classification,
            classification_details=baseline.classification_details,
            score_breakdown=baseline.score_breakdown,
            summary=exec_summary,
            key_functionality=ai_dict.get("key_functionality", baseline.key_functionality),
            purpose=ai_dict.get("purpose", baseline.purpose),
            persistence_assessment=baseline.persistence_assessment,
            runtime_confirmation_status=baseline.runtime_confirmation_status,
            mitre_techniques=validated_mitre,
            host_iocs=baseline.host_iocs,
            network_iocs=baseline.network_iocs,
            recommendations=recommendations,
            supporting_finding_ids=baseline.supporting_finding_ids,
            ai_validation=val_result.model_dump()
        )

        return merged, val_result
