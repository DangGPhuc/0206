"""
0206 - Grounded AI Package
Phase 17, 18, 19: Non-authoritative, evidence-grounded AI synthesis.
"""
from ai.agent import LLMThreatSynthesizer
from ai.validation.schema import (
    AIFieldStatus,
    AIValidationDecision,
    AIValidationResult,
)
from ai.grounding.validator import GroundingValidator
from ai.providers import (
    AIProvider,
    OfflineAIProvider,
    OpenAIProvider,
    OllamaProvider,
    AnthropicProvider,
)
from ai.prompts import (
    BASIC_SYSTEM_PROMPT,
    BASIC_USER_PROMPT_TEMPLATE,
    ADVANCED_SYSTEM_PROMPT,
    ADVANCED_USER_PROMPT_TEMPLATE,
    GROUNDED_SYSTEM_PROMPT,
    GROUNDED_USER_PROMPT_TEMPLATE,
)

__all__ = [
    "LLMThreatSynthesizer",
    "AIFieldStatus",
    "AIValidationDecision",
    "AIValidationResult",
    "GroundingValidator",
    "AIProvider",
    "OfflineAIProvider",
    "OpenAIProvider",
    "OllamaProvider",
    "AnthropicProvider",
    "BASIC_SYSTEM_PROMPT",
    "BASIC_USER_PROMPT_TEMPLATE",
    "ADVANCED_SYSTEM_PROMPT",
    "ADVANCED_USER_PROMPT_TEMPLATE",
    "GROUNDED_SYSTEM_PROMPT",
    "GROUNDED_USER_PROMPT_TEMPLATE",
]
