"""
0206 - Ollama Local Provider
"""
import os
import json
from typing import Dict, Any, List, Optional
from core.evidence import EvidenceStore
from core.findings import Finding
from core.privacy import PrivacyRedactor
from ai.providers.base import AIProvider


class OllamaProvider(AIProvider):
    """Local Ollama provider via OpenAI-compatible endpoints."""

    def __init__(
        self,
        api_base: Optional[str] = None,
        model: Optional[str] = None,
        privacy_mode: str = "strict"
    ):
        self.api_base = api_base or os.getenv("OLLAMA_API_BASE", "http://localhost:11434/v1")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3")
        self.redactor = PrivacyRedactor(mode=privacy_mode)

    @property
    def name(self) -> str:
        return "ollama"

    def is_available(self) -> bool:
        return bool(self.api_base)

    def synthesize(
        self,
        evidence_store: EvidenceStore,
        findings: List[Finding],
        system_prompt: str,
        user_prompt: str,
    ) -> Dict[str, Any]:
        from openai import OpenAI
        client = OpenAI(base_url=self.api_base, api_key="ollama")
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
