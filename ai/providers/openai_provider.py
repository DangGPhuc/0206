"""
0206 - OpenAI-Compatible AI Provider
Phase 17: Provider implementation for OpenAI-compatible APIs.
Enforces credential isolation: only inspects OPENAI_API_KEY, OPENAI_MODEL, OPENAI_API_BASE.
"""
import os
import json
from typing import Dict, Any, List, Optional
from core.evidence import EvidenceStore
from core.findings import Finding
from core.privacy import PrivacyRedactor
from ai.providers.base import AIProvider


class OpenAIProvider(AIProvider):
    """OpenAI API Provider (e.g. gpt-4o)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        model: Optional[str] = None,
        privacy_mode: str = "strict"
    ):
        # Strictly isolated: only OpenAI credentials/models
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.api_base = api_base or os.getenv("OPENAI_API_BASE", "")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o")
        self.redactor = PrivacyRedactor(mode=privacy_mode)

    @property
    def name(self) -> str:
        return "openai"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def synthesize(
        self,
        request: Optional[Any] = None,
        evidence_store: Optional[EvidenceStore] = None,
        findings: Optional[List[Finding]] = None,
        system_prompt: Optional[str] = None,
        user_prompt: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        from openai import OpenAI

        sys_prompt = getattr(request, "system_prompt", None) or system_prompt or ""
        usr_prompt = getattr(request, "user_prompt", None) or user_prompt or ""
        req_model = getattr(request, "model", None) or self.model

        client_kwargs: Dict[str, Any] = {"api_key": self.api_key}
        if self.api_base:
            client_kwargs["base_url"] = self.api_base

        client = OpenAI(**client_kwargs)
        response = client.chat.completions.create(
            model=req_model,
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": usr_prompt}
            ],
            temperature=0.1,
            response_format={"type": "json_object"}
        )
        content = response.choices[0].message.content or "{}"
        return json.loads(content)
