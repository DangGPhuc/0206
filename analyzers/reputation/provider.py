"""
0206 - Reputation Analysis Provider Interface
Enforces:
- HASH LOOKUP ONLY by default.
- Never automatically uploads malware binaries.
- Never equates NOT_FOUND with CLEAN.
"""
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ReputationStatus(str, Enum):
    KNOWN_MALICIOUS = "KNOWN_MALICIOUS"
    KNOWN_SUSPICIOUS = "KNOWN_SUSPICIOUS"
    LOW_DETECTION = "LOW_DETECTION"
    NOT_FOUND = "NOT_FOUND"
    LOOKUP_FAILED = "LOOKUP_FAILED"
    NOT_CHECKED = "NOT_CHECKED"


class ReputationResult(BaseModel):
    """Normalized hash reputation result from an intelligence provider."""
    provider: str
    query_hash: str
    status: ReputationStatus = ReputationStatus.NOT_CHECKED
    detection_count: int = 0
    total_engines: int = 0
    malware_names: List[str] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_analysis: Optional[str] = None
    raw_response_hash: Optional[str] = None
    privacy_policy: str = "HASH_LOOKUP_ONLY"
    details: str = ""

    class Config:
        use_enum_values = True


class ReputationProvider(ABC):
    """Abstract interface for hash reputation lookup providers."""

    @abstractmethod
    def lookup_hash(self, sha256_hash: str, evidence_store: Optional[Any] = None) -> ReputationResult:
        """Looks up the sample hash without uploading sample bytes."""
        pass
