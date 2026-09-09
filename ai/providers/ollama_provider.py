"""
0206 - Ollama Local Provider
Phase 17: Local Ollama provider via OpenAI-compatible endpoints.
Enforces credential isolation: operates strictly locally, never consumes OpenAI/Anthropic credentials.
"""
import os
import json
from typing import Dict, Any, List, Optional
from core.evidence import EvidenceStore
from core.findings import Finding
from core.privacy import PrivacyRedactor
from ai.providers.base import AIProvider


class OllamaProvider(AIProvider):
    """Local Ollama provider via local OpenAI-compatible endpoints."""

    def __init__(
        self,
        api_base: Optional[str] = None,
        model: Optional[str] = None,
        privacy_mode: str = "strict"
    ):
        # Local endpoint only, never consumes cloud API keys
        endpoint = api_base or os.getenv("OLLAMA_API_BASE") or os.getenv("OLLAMA_HOST")
        if endpoint and not endpoint.startswith("http"):
            endpoint = f"http://{endpoint}"
        if endpoint and not endpoint.endswith("/v1"):
            endpoint = f"{endpoint.rstrip('/')}/v1"
        self.api_base = endpoint or "http://localhost:11434/v1"
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3")
        self.redactor = PrivacyRedactor(mode=privacy_mode)

    @property
    def name(self) -> str:
        return "ollama"

    def is_available(self) -> bool:
        return bool(self.api_base)

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

        client = OpenAI(base_url=self.api_base, api_key="ollama")
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
