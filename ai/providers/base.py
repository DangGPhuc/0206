"""
0206 - AI Provider Abstract Base Class
Phase 17: Provider interface for optional AI synthesis.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from core.evidence import EvidenceStore
from core.findings import Finding


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
        evidence_store: EvidenceStore,
        findings: List[Finding],
        system_prompt: str,
        user_prompt: str,
    ) -> Dict[str, Any]:
        """Queries provider with privacy-sanitized inputs and returns parsed JSON."""
        pass
