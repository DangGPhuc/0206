"""
0206 - AI Provider Abstract Base Class
Phase 17: Provider interface for optional AI synthesis.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union, TYPE_CHECKING
from core.evidence import EvidenceStore
from core.findings import Finding

if TYPE_CHECKING:
    from ai.schema import SanitizedAIRequest


class AIProvider(ABC):
    """Abstract interface for LLM synthesis providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def synthesize(
        self,
        request: Optional[Any] = None,
        evidence_store: Optional[EvidenceStore] = None,
        findings: Optional[List[Finding]] = None,
        system_prompt: Optional[str] = None,
        user_prompt: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Queries provider with allowlisted sanitized request or legacy parameters."""
        pass
