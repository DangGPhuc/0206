"""
0206 - Grounded AI Threat Synthesizer Module
Enforces:
1. AI is strictly non-authoritative: cannot override threat score, threat level, or invent IOCs.
2. Mandatory privacy redaction BEFORE any remote transmission.
3. Strict evidence citation validation via AIValidationResult (ACCEPTED, DOWNGRADED, REJECTED).
4. Real provider abstraction (Offline, OpenAI, Anthropic, Ollama); zero HTTP logic in agent.
5. Deterministic offline fallback using FindingEngine.
6. Strict provider credential isolation (each provider only accesses its own config/credentials).
7. Allowlist-projected SanitizedAIRequest envelope with untrusted literal tagging.
8. Grounded evidence selection based on finding citation graphs.
"""
import os
import json
from typing import Dict, Any, Optional, List, Union

from core.evidence import EvidenceStore
from core.findings import Finding, FindingEngine, Assessment
from core.privacy import PrivacyRedactor, DLPStatus, DLPViolationError
from ai.prompts import GROUNDED_SYSTEM_PROMPT, GROUNDED_USER_PROMPT_TEMPLATE
from ai.schema import ProviderConfig, SanitizedAIRequest
from ai.validation.schema import (
    AIFieldStatus,
    AIValidationDecision,
    AIValidationResult,
)
from ai.grounding.validator import GroundingValidator
from ai.providers.base import AIProvider
from ai.providers.offline import OfflineAIProvider
from ai.providers.openai_provider import OpenAIProvider
from ai.providers.anthropic_provider import AnthropicProvider
from ai.providers.ollama_provider import OllamaProvider


class LLMThreatSynthesizer:
    """Orchestrates AI enrichment with strict evidence grounding and provider abstraction."""

    def __init__(
        self,
        provider: Union[str, AIProvider] = "auto",
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        model: Optional[str] = None,
        privacy_mode: str = "strict",
        config: Optional[ProviderConfig] = None
    ):
        self.privacy_mode = privacy_mode
        self.privacy_redactor = PrivacyRedactor(mode=privacy_mode)

        if isinstance(provider, AIProvider):
            self.provider_instance: AIProvider = provider
            self.provider = provider.name
            self.model = getattr(provider, "model", "custom")
            self.api_key = getattr(provider, "api_key", None)
            return

        p_str = provider.lower() if isinstance(provider, str) else "auto"
        if p_str == "auto":
            if os.getenv("OPENAI_API_KEY"):
                p_str = "openai"
            elif os.getenv("ANTHROPIC_API_KEY"):
                p_str = "anthropic"
            elif os.getenv("OLLAMA_API_BASE") or os.getenv("OLLAMA_HOST"):
                p_str = "ollama"
            else:
                p_str = "offline"

        self.provider = p_str

        # Resolve credentials strictly per provider to prevent credential leakage
        if self.provider == "openai":
            eff_key = api_key or (config.api_key if config else None) or os.getenv("OPENAI_API_KEY", "")
            eff_base = api_base or (config.endpoint if config else None) or os.getenv("OPENAI_API_BASE", "")
            eff_model = model or (config.model if config else None) or os.getenv("OPENAI_MODEL", "gpt-4o")
            self.api_key = eff_key
            self.model = eff_model
            self.provider_instance = OpenAIProvider(
                api_key=eff_key,
                api_base=eff_base,
                model=eff_model,
                privacy_mode=privacy_mode
            )
        elif self.provider == "anthropic":
            eff_key = api_key or (config.api_key if config else None) or os.getenv("ANTHROPIC_API_KEY", "")
            eff_model = model or (config.model if config else None) or os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
            self.api_key = eff_key
            self.model = eff_model
            self.provider_instance = AnthropicProvider(
                api_key=eff_key,
                model=eff_model,
                privacy_mode=privacy_mode
            )
        elif self.provider == "ollama":
            eff_base = api_base or (config.endpoint if config else None) or os.getenv("OLLAMA_API_BASE", "") or os.getenv("OLLAMA_HOST", "")
            eff_model = model or (config.model if config else None) or os.getenv("OLLAMA_MODEL", "llama3")
            self.api_key = None
            self.model = eff_model
            self.provider_instance = OllamaProvider(
                api_base=eff_base,
                model=eff_model,
                privacy_mode=privacy_mode
            )
        else:
            self.provider = "offline"
            self.api_key = None
            self.model = "offline"
            self.provider_instance = OfflineAIProvider()

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

        if self.provider_instance.is_available() and self.provider != "offline":
            try:
                ai_dict = self._call_llm(evidence_store, findings)
                validator = GroundingValidator(evidence_store)
                assessment, _ = validator.validate_synthesis(ai_dict, baseline_assessment, findings=findings)
                return assessment
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
        """Calls configured AI provider with allowlist-projected, privacy-redacted and DLP-cleared inputs."""
        # 1. Collect every Evidence ID referenced by findings
        referenced_eids = set()
        for f in findings:
            referenced_eids.update(f.source_evidence_ids)

        # 2. Select referenced evidence records
        selected_records = []
        for eid in sorted(referenced_eids):
            rec = evidence_store.get(eid)
            if rec:
                selected_records.append(rec)

        # 3. Supplemental contextual records up to a reasonable cap
        remaining_slots = max(0, 50 - len(selected_records))
        if remaining_slots > 0:
            for rec in sorted(evidence_store.all(), key=lambda r: r.evidence_id):
                if rec.evidence_id not in referenced_eids:
                    selected_records.append(rec)
                    if len(selected_records) >= 50:
                        break

        # 4. Project allowlist of fields and tag values as UNTRUSTED_LITERAL to thwart prompt injection
        projected_evidence = []
        for rec in selected_records:
            projected_evidence.append({
                "evidence_id": rec.evidence_id,
                "domain": rec.domain.value if hasattr(rec.domain, "value") else str(rec.domain),
                "field": rec.field,
                "value_type": "UNTRUSTED_LITERAL",
                "value": rec.value,
                "confidence": rec.confidence
            })

        projected_findings = []
        for f in findings:
            projected_findings.append({
                "finding_id": f.finding_id,
                "domain": f.domain.value if hasattr(f.domain, "value") else str(f.domain),
                "title": f.title,
                "confidence": f.confidence,
                "evidence_ids": f.source_evidence_ids,
                "mitre_attack_id": f.mitre_attack_id,
                "why_it_matters": f.why_it_matters or f.details
            })

        # 5. Redact allowlist-projected data before prompt formatting
        clean_evidence = self.privacy_redactor.redact(projected_evidence)
        clean_findings = self.privacy_redactor.redact(projected_findings)

        user_prompt = GROUNDED_USER_PROMPT_TEMPLATE.format(
            evidence_json=json.dumps(clean_evidence, indent=2),
            findings_json=json.dumps(clean_findings, indent=2)
        )

        # 6. Construct typed SanitizedAIRequest envelope
        request_envelope = SanitizedAIRequest(
            evidence_records=clean_evidence,
            findings=clean_findings,
            system_prompt=GROUNDED_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            included_evidence_ids=[r["evidence_id"] for r in clean_evidence],
            provider=self.provider,
            model=self.model
        )

        # 7. Pre-flight DLP transmission audit on the sanitized envelope
        audit_res = self.privacy_redactor.audit_for_transmission(request_envelope.model_dump())
        if not audit_res.is_safe or audit_res.status == DLPStatus.BLOCKED:
            raise DLPViolationError(f"DLP transmission gate blocked request: {'; '.join(audit_res.violations)}")

        # 8. Delegate execution to AIProvider abstraction passing sanitized envelope
        return self.provider_instance.synthesize(request=request_envelope)

    def _merge_and_validate(
        self,
        ai_dict: Dict[str, Any],
        baseline: Assessment,
        evidence_store: EvidenceStore,
        findings: Optional[List[Finding]] = None
    ) -> Assessment:
        """Compatibility wrapper delegating directly to GroundingValidator."""
        validator = GroundingValidator(evidence_store)
        assessment, _ = validator.validate_synthesis(ai_dict, baseline, findings=findings)
        return assessment
