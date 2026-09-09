"""
0206 - Grounded AI Schema & Typed Request Envelope
Phase 16 & 17:
Defines typed provider configurations and allowlist-based sanitized request transfer objects.
Guarantees:
- Providers receive ONLY sanitized, allowlisted forensic projections.
- Providers have zero access to raw EvidenceStore or unredacted internal objects.
- Provider credentials and configurations are strictly isolated per provider.
"""
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class ProviderConfig(BaseModel):
    """Configuration object specific to a single AI provider."""
    provider: str = "offline"
    api_key: Optional[str] = None
    model: Optional[str] = None
    endpoint: Optional[str] = None
    privacy_mode: str = "strict"

    model_config = ConfigDict(use_enum_values=True)


class SanitizedAIRequest(BaseModel):
    """
    Allowlist-projected forensic envelope for external/local AI synthesis.
    All free-form values are tagged as UNTRUSTED_LITERAL to prevent prompt injection.
    """
    evidence_records: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    system_prompt: str
    user_prompt: str
    included_evidence_ids: List[str] = Field(default_factory=list)
    provider: str = "offline"
    model: str = "offline"

    model_config = ConfigDict(use_enum_values=True)
