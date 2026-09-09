"""
0206 - Grounded AI Threat Synthesizer Module
Enforces:
1. AI is strictly non-authoritative: cannot override threat score, threat level, or invent IOCs.
2. Mandatory privacy redaction BEFORE any remote transmission.
3. Strict evidence citation validation via AIValidationResult (ACCEPTED, DOWNGRADED, REJECTED).
4. Real provider abstraction (Offline, OpenAI, Anthropic, Ollama); zero HTTP logic in agent.
5. Deterministic offline fallback using FindingEngine.
"""
import os
import json
from typing import Dict, Any, Optional, List, Union

from core.evidence import EvidenceStore
from core.findings import Finding, FindingEngine, Assessment
from core.privacy import PrivacyRedactor, DLPStatus, DLPViolationError
from ai.prompts import GROUNDED_SYSTEM_PROMPT, GROUNDED_USER_PROMPT_TEMPLATE
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
        privacy_mode: str = "strict"
    ):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "") or os.getenv("ANTHROPIC_API_KEY", "")
        self.api_base = api_base or os.getenv("OPENAI_API_BASE", "") or os.getenv("OLLAMA_API_BASE", "")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o")
        self.privacy_mode = privacy_mode
        self.privacy_redactor = PrivacyRedactor(mode=privacy_mode)

        if isinstance(provider, AIProvider):
            self.provider_instance: AIProvider = provider
            self.provider = provider.name
        else:
            p_str = provider.lower() if isinstance(provider, str) else "auto"
            if p_str == "auto":
                if os.getenv("OPENAI_API_KEY"):
                    p_str = "openai"
                elif os.getenv("ANTHROPIC_API_KEY"):
                    p_str = "anthropic"
                elif self.api_base and "11434" in self.api_base:
                    p_str = "ollama"
                else:
                    p_str = "offline"
            self.provider = p_str
            if self.provider == "openai":
                self.provider_instance = OpenAIProvider(api_key=self.api_key, api_base=self.api_base, model=self.model, privacy_mode=privacy_mode)
            elif self.provider == "anthropic":
                self.provider_instance = AnthropicProvider(api_key=self.api_key, model=self.model, privacy_mode=privacy_mode)
            elif self.provider == "ollama":
                self.provider_instance = OllamaProvider(api_base=self.api_base, model=self.model, privacy_mode=privacy_mode)
            else:
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
        """Calls configured AI provider with privacy-redacted and DLP-cleared inputs."""
        # Redact evidence and findings BEFORE formatting prompts
        clean_evidence = self.privacy_redactor.redact(evidence_store.to_dict()[:50])
        clean_findings = self.privacy_redactor.redact([f.model_dump() for f in findings])

        user_prompt = GROUNDED_USER_PROMPT_TEMPLATE.format(
            evidence_json=json.dumps(clean_evidence, indent=2),
            findings_json=json.dumps(clean_findings, indent=2)
        )

        # Immediate pre-flight DLP audit on the exact prompts and provider before remote request
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

        # Delegate execution to AIProvider abstraction (no HTTP logic in agent)
        return self.provider_instance.synthesize(
            evidence_store=evidence_store,
            findings=findings,
            system_prompt=GROUNDED_SYSTEM_PROMPT,
            user_prompt=user_prompt
        )

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
