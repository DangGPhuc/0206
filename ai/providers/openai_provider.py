"""
0206 - OpenAI-Compatible AI Provider
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
        evidence_store: EvidenceStore,
        findings: List[Finding],
        system_prompt: str,
        user_prompt: str,
    ) -> Dict[str, Any]:
        from openai import OpenAI
        client_kwargs: Dict[str, Any] = {"api_key": self.api_key}
        if self.api_base:
            client_kwargs["base_url"] = self.api_base

        client = OpenAI(**client_kwargs)
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,
            response_format={"type": "json_object"}
        )
        content = response.choices[0].message.content or "{}"
        return json.loads(content)
