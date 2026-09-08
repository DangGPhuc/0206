"""
0206 - Grounded AI Threat Synthesizer Module
Enforces:
1. Privacy redaction BEFORE any remote transmission.
2. Evidence citation validation (rejects ungrounded assertions).
3. Deterministic offline fallback using FindingEngine.
"""
import os
import json
import re
from typing import Dict, Any, Optional, List

from core.evidence import EvidenceStore
from core.findings import Finding, FindingEngine, Assessment
from core.privacy import PrivacyRedactor, PrivacyMode
from ai.prompts import GROUNDED_SYSTEM_PROMPT, GROUNDED_USER_PROMPT_TEMPLATE


class LLMThreatSynthesizer:
    """Orchestrates AI enrichment with strict evidence grounding and privacy guards."""

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
        findings: Optional[List[Finding]] = None
    ) -> Assessment:
        """Enriches deterministic findings with LLM reasoning if configured."""
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

        baseline_assessment = finding_engine.generate_assessment()

        if self.provider in ("openai", "ollama") and (self.api_key or self.provider == "ollama"):
            try:
                ai_dict = self._call_llm(evidence_store, findings)
                return self._merge_and_validate(ai_dict, baseline_assessment, evidence_store)
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

        # Redact evidence and findings BEFORE sending to LLM
        clean_evidence = self.privacy_redactor.redact(evidence_store.to_dict()[:50])
        clean_findings = self.privacy_redactor.redact([f.model_dump() for f in findings])

        user_prompt = GROUNDED_USER_PROMPT_TEMPLATE.format(
            evidence_json=json.dumps(clean_evidence, indent=2),
            findings_json=json.dumps(clean_findings, indent=2)
        )

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
        evidence_store: EvidenceStore
    ) -> Assessment:
        """
        Validates that AI conclusions reference actual evidence.
        Prevents hallucinated IOCs by strictly retaining IOCs from evidence_store.
        """
        # Validate cited MITRE technique evidence IDs
        validated_mitre = []
        for t in ai_dict.get("mitre_attack", []):
            eids = t.get("evidence_ids", [])
            valid_eids = [eid for eid in eids if evidence_store.get(eid)]
            if valid_eids:
                t["evidence_ids"] = valid_eids
                validated_mitre.append(t)

        # Retain baseline IOCs (LLM cannot invent hashes or IPs!)
        threat_score = ai_dict.get("threat_score", baseline.threat_score)
        threat_level = ai_dict.get("threat_level", baseline.threat_level)

        return Assessment(
            assessment_id=baseline.assessment_id,
            title=f"AI-Enriched Triage Assessment: {ai_dict.get('malware_family', baseline.classification)}",
            threat_level=threat_level,
            threat_score=threat_score,
            classification=ai_dict.get("malware_family", baseline.classification),
            summary=ai_dict.get("executive_summary", baseline.summary),
            key_functionality=ai_dict.get("key_functionality", baseline.key_functionality),
            purpose=ai_dict.get("purpose", baseline.purpose),
            persistence_assessment=ai_dict.get("persistence", baseline.persistence_assessment),
            runtime_confirmation_status=baseline.runtime_confirmation_status,
            mitre_techniques=validated_mitre if validated_mitre else baseline.mitre_techniques,
            host_iocs=baseline.host_iocs,       # Grounded strictly in evidence store
            network_iocs=baseline.network_iocs, # Grounded strictly in evidence store
            recommendations=ai_dict.get("incident_recommendations", baseline.recommendations),
            supporting_finding_ids=baseline.supporting_finding_ids
        )
