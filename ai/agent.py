"""
0206 - Grounded AI Threat Synthesizer Module
Enforces:
1. AI is strictly non-authoritative: cannot override threat score, threat level, or invent IOCs.
2. Mandatory privacy redaction BEFORE any remote transmission.
3. Strict evidence citation validation via AIValidationResult (ACCEPTED, DOWNGRADED, REJECTED).
4. Deterministic offline fallback using FindingEngine.
"""
from enum import Enum
import os
import json
import re
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

from core.evidence import EvidenceStore
from core.findings import Finding, FindingEngine, Assessment
from core.privacy import PrivacyRedactor, PrivacyMode, DLPStatus, DLPViolationError
from ai.prompts import GROUNDED_SYSTEM_PROMPT, GROUNDED_USER_PROMPT_TEMPLATE


class AIFieldStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    DOWNGRADED = "DOWNGRADED"
    REJECTED = "REJECTED"


class AIValidationDecision(BaseModel):
    field: str
    status: AIFieldStatus
    reason: str
    original_value: Any = None
    resolved_value: Any = None


class AIValidationResult(BaseModel):
    """Audit record evaluating AI proposals against ground truth evidence."""
    decisions: List[AIValidationDecision] = Field(default_factory=list)
    decisions_by_field: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    rejected_fields: List[str] = Field(default_factory=list)
    downgraded_fields: List[str] = Field(default_factory=list)
    accepted_fields: List[str] = Field(default_factory=list)
    validated_hypotheses: List[Dict[str, Any]] = Field(default_factory=list)



class LLMThreatSynthesizer:
    """Orchestrates AI enrichment with strict evidence grounding and validation boundaries."""

    def __init__(
        self,
        provider: str = "auto",
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        model: Optional[str] = None,
        privacy_mode: str = "strict"
    ):
        self.provider = provider.lower()
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.api_base = api_base or os.getenv("OPENAI_API_BASE", "")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o")
        self.privacy_redactor = PrivacyRedactor(mode=privacy_mode)

        # Auto-detect mode
        if self.provider == "auto":
            if self.api_key:
                self.provider = "openai"
            elif self.api_base and "11434" in self.api_base:
                self.provider = "ollama"
            else:
                self.provider = "offline"

    def synthesize(
        self,
        evidence_store: Any,
        findings: Optional[List[Finding]] = None,
        base_assessment: Optional[Assessment] = None
    ) -> Assessment:
        """Enriches deterministic findings with validated LLM hypotheses if configured."""
        if isinstance(evidence_store, dict):
            # Legacy compatibility mode
            dict_data = evidence_store
            store = EvidenceStore()
            st = dict_data.get("static", {}).get("file_info", {})
            if st.get("sha256"):
                store.create(st.get("file_name", "sample"), "FILE_METADATA", "sha256", st["sha256"], "Legacy")
            finding_engine = FindingEngine(store)
            findings = finding_engine.analyze()
            evidence_store = store
        elif findings is None:
            finding_engine = FindingEngine(evidence_store)
            findings = finding_engine.analyze()
        else:
            finding_engine = FindingEngine(evidence_store)

        baseline_assessment = base_assessment if base_assessment is not None else finding_engine.generate_assessment()


        if self.provider in ("openai", "ollama") and (self.api_key or self.provider == "ollama"):
            try:
                ai_dict = self._call_llm(evidence_store, findings)
                return self._merge_and_validate(ai_dict, baseline_assessment, evidence_store, findings=findings)
            except Exception as e:
                # Seamless fallback to deterministic assessment
                baseline_assessment.summary += f" [Note: AI enrichment unavailable ({e}); deterministic assessment utilized]."
                return baseline_assessment
        else:
            return baseline_assessment

    def _call_llm(
        self,
        evidence_store: EvidenceStore,
        findings: List[Finding]
    ) -> Dict[str, Any]:
        """Calls OpenAI or Ollama endpoint with privacy-redacted inputs."""
        from openai import OpenAI
        client_kwargs: Dict[str, Any] = {}
        if self.api_base:
            client_kwargs["base_url"] = self.api_base
        if self.api_key:
            client_kwargs["api_key"] = self.api_key
        elif self.provider == "ollama":
            client_kwargs["api_key"] = "ollama"
            if not self.api_base:
                client_kwargs["base_url"] = "http://localhost:11434/v1"

        client = OpenAI(**client_kwargs)

        # Redact evidence and findings BEFORE formatting prompts
        clean_evidence = self.privacy_redactor.redact(evidence_store.to_dict()[:50])
        clean_findings = self.privacy_redactor.redact([f.model_dump() for f in findings])

        user_prompt = GROUNDED_USER_PROMPT_TEMPLATE.format(
            evidence_json=json.dumps(clean_evidence, indent=2),
            findings_json=json.dumps(clean_findings, indent=2)
        )

        # Immediate pre-flight DLP audit on the exact prompts and provider before remote request (Phase 3 & P0.3)
        audit_payload = {
            "provider": self.provider,
            "model": self.model,
            "evidence": clean_evidence,
            "findings": clean_findings,
            "system_prompt": GROUNDED_SYSTEM_PROMPT,
            "user_prompt": user_prompt
        }
        audit_res = self.privacy_redactor.audit_for_transmission(audit_payload)
        if not audit_res.is_safe or audit_res.status == DLPStatus.BLOCKED:
            raise DLPViolationError(f"DLP transmission gate blocked request: {'; '.join(audit_res.violations)}")

        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": GROUNDED_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,
            response_format={"type": "json_object"}
        )

        raw_content = response.choices[0].message.content or "{}"
        try:
            return json.loads(raw_content)
        except json.JSONDecodeError:
            cleaned = re.sub(r'^```json\s*', '', raw_content.strip())
            cleaned = re.sub(r'\s*```$', '', cleaned)
            return json.loads(cleaned)

    def _merge_and_validate(
        self,
        ai_dict: Dict[str, Any],
        baseline: Assessment,
        evidence_store: EvidenceStore,
        findings: Optional[List[Finding]] = None
    ) -> Assessment:
        """
        Validates AI suggestions against ground truth evidence.
        AI CANNOT override threat scores, levels, or invent IOCs.
        """
        val_result = AIValidationResult()

        def add_decision(field: str, status: AIFieldStatus, reason: str, orig: Any, res: Any):
            dec = AIValidationDecision(
                field=field,
                status=status,
                reason=reason,
                original_value=orig,
                resolved_value=res
            )
            val_result.decisions.append(dec)
            val_result.decisions_by_field[field] = dec.model_dump()
            if status == AIFieldStatus.REJECTED:
                val_result.rejected_fields.append(field)
            elif status == AIFieldStatus.DOWNGRADED:
                val_result.downgraded_fields.append(field)
            else:
                val_result.accepted_fields.append(field)


        # 1. Threat score & Threat level: AI is NEVER AUTHORITATIVE!
        if "threat_score" in ai_dict and ai_dict["threat_score"] != baseline.threat_score:
            add_decision(
                "threat_score", AIFieldStatus.REJECTED,
                "Threat score is authoritative from deterministic FindingEngine; LLM override rejected.",
                ai_dict["threat_score"], baseline.threat_score
            )
        if "threat_level" in ai_dict and ai_dict["threat_level"] != baseline.threat_level:
            add_decision(
                "threat_level", AIFieldStatus.REJECTED,
                "Threat level is authoritative from deterministic FindingEngine; LLM override rejected.",
                ai_dict["threat_level"], baseline.threat_level
            )

        # 2. IOCs: AI cannot invent hashes, paths, domains, or IPs
        for ioc_field in ("host_iocs", "network_iocs", "hashes", "paths", "domains", "ips", "ioc_values"):
            if ioc_field in ai_dict:
                add_decision(
                    ioc_field, AIFieldStatus.REJECTED,
                    f"IOC field '{ioc_field}' cannot be authored by AI; strictly derived from EvidenceStore facts.",
                    ai_dict.get(ioc_field), getattr(baseline, ioc_field, None)
                )

        # 2b. High-impact behavioral claims (C2 confirmation, process injection confirmation, persistence claims)
        if "c2_confirmation" in ai_dict:
            has_c2_fact = any("CONFIRMED_C2" in f.title for f in findings or [])
            if not has_c2_fact:
                add_decision(
                    "c2_confirmation", AIFieldStatus.REJECTED,
                    "AI C2 confirmation rejected; multi-source corroboration required for confirmed C2.",
                    ai_dict.get("c2_confirmation"), False
                )
            else:
                add_decision(
                    "c2_confirmation", AIFieldStatus.ACCEPTED,
                    "C2 confirmation grounded in verified multi-source evidence.",
                    ai_dict.get("c2_confirmation"), True
                )

        if "process_injection_confirmation" in ai_dict:
            add_decision(
                "process_injection_confirmation", AIFieldStatus.DOWNGRADED,
                "Process injection confirmation downgraded; static API imports establish potential capability only, not confirmed execution.",
                ai_dict.get("process_injection_confirmation"), "CAPABILITY_UNCONFIRMED_RUNTIME"
            )

        if "persistence_claims" in ai_dict:
            has_pers = any(f.category == FindingCategory.PERSISTENCE for f in findings or [])
            if not has_pers:
                add_decision(
                    "persistence_claims", AIFieldStatus.REJECTED,
                    "Persistence claim rejected; no autostart registry or service evidence found in EvidenceStore.",
                    ai_dict.get("persistence_claims"), None
                )
            else:
                add_decision(
                    "persistence_claims", AIFieldStatus.ACCEPTED,
                    "Persistence claim corroborated by host telemetry evidence.",
                    ai_dict.get("persistence_claims"), baseline.persistence_assessment
                )

        # 3. Malware family claim: DOWNGRADE to unconfirmed hypothesis
        resolved_classification = baseline.classification
        ai_family = ai_dict.get("malware_family") or ai_dict.get("classification")
        if ai_family and ai_family.lower() not in (baseline.classification.lower(), "unknown", "generic"):
            add_decision(
                "malware_family", AIFieldStatus.DOWNGRADED,
                "Unverified malware family claim downgraded to heuristic hypothesis.",
                ai_family, f"{baseline.classification} (Hypothesis: {ai_family}) [UNCONFIRMED]"
            )

            resolved_classification = f"{baseline.classification} (Hypothesis: {ai_family}) [UNCONFIRMED]"
            val_result.validated_hypotheses.append({
                "type": "malware_family",
                "hypothesis": ai_family,
                "status": "UNCONFIRMED_HYPOTHESIS"
            })
        else:
            add_decision(
                "malware_family", AIFieldStatus.ACCEPTED,
                "Baseline classification preserved.",
                ai_family, baseline.classification
            )

        # 4. MITRE ATT&CK: Validate cited evidence IDs
        validated_mitre = list(baseline.mitre_techniques)
        mitre_entries = ai_dict.get("mitre_attack") or ai_dict.get("mitre_techniques") or []
        for t in mitre_entries:
            eids = t.get("evidence_ids", [])

            valid_eids = [eid for eid in eids if evidence_store.get(eid)]
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

        if not findings or baseline.threat_score == 0:
            recommendations = baseline.recommendations
            resolved_purpose = baseline.purpose or "NOT_ESTABLISHED"
            add_decision("recommendations", AIFieldStatus.REJECTED, "Threat score is 0 / no findings; active incident containment suppressed.", None, None)
        else:
            recommendations = ai_dict.get("incident_recommendations") or baseline.recommendations
            resolved_purpose = ai_dict.get("purpose", baseline.purpose)
            add_decision("recommendations", AIFieldStatus.ACCEPTED, "Advisory response recommendations accepted.", None, None)

        return Assessment(
            assessment_id=baseline.assessment_id,
            title=f"Triage Assessment: {resolved_classification}",
            threat_level=baseline.threat_level,    # Deterministic authority preserved
            threat_score=baseline.threat_score,    # Deterministic authority preserved
            classification=resolved_classification,
            classification_details=baseline.classification_details,
            score_breakdown=baseline.score_breakdown,
            summary=exec_summary,
            key_functionality=ai_dict.get("key_functionality", baseline.key_functionality),
            purpose=resolved_purpose,
            persistence_assessment=baseline.persistence_assessment,
            runtime_confirmation_status=baseline.runtime_confirmation_status,
            coverage=baseline.coverage,
            mitre_techniques=validated_mitre,
            host_iocs=baseline.host_iocs,
            network_iocs=baseline.network_iocs,
            recommendations=recommendations,
            supporting_finding_ids=baseline.supporting_finding_ids,
            evidence_graph_nodes=baseline.evidence_graph_nodes,
            confidence=baseline.confidence,
            classification_confidence=baseline.classification_confidence,
            analysis_confidence=baseline.analysis_confidence,
            ai_validation=val_result.model_dump()
        )
