"""
0206 - Anthropic AI Provider
"""
import os
import json
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
        evidence_store: EvidenceStore,
        findings: List[Finding],
        system_prompt: str,
        user_prompt: str,
    ) -> Dict[str, Any]:
        # Anthropic API call with json parsing
        import urllib.request
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        body = {
            "model": self.model,
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}]
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
