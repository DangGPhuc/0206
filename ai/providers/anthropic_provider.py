"""
0206 - Anthropic AI Provider
Phase 17: Provider implementation for Anthropic Claude APIs.
Enforces credential isolation: only inspects ANTHROPIC_API_KEY and ANTHROPIC_MODEL.
"""
import os
import json
import urllib.request
from typing import Dict, Any, List, Optional
from core.evidence import EvidenceStore
from core.findings import Finding
from core.privacy import PrivacyRedactor
from ai.providers.base import AIProvider


class AnthropicProvider(AIProvider):
    """Anthropic Claude API Provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        privacy_mode: str = "strict"
    ):
        # Strictly isolated: only Anthropic credentials/models
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        self.redactor = PrivacyRedactor(mode=privacy_mode)

    @property
    def name(self) -> str:
        return "anthropic"

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
        sys_prompt = getattr(request, "system_prompt", None) or system_prompt or ""
        usr_prompt = getattr(request, "user_prompt", None) or user_prompt or ""
        req_model = getattr(request, "model", None) or self.model

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        body = {
            "model": req_model,
            "max_tokens": 4096,
            "system": sys_prompt,
            "messages": [{"role": "user", "content": usr_prompt}]
        }
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data["content"][0]["text"]
            return json.loads(text)
