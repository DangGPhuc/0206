"""
0206 - AI Validation Schema
Phase 17: Schemas for auditing and validating AI model suggestions against ground truth evidence.
"""
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class AIFieldStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    DOWNGRADED = "DOWNGRADED"
    REJECTED = "REJECTED"


class AIValidationDecision(BaseModel):
    field: str
    status: AIFieldStatus
    reason: str
    original_value: Any = None
    resolved_value: Any = None


class AIValidationResult(BaseModel):
    """Audit record evaluating AI proposals against ground truth evidence."""
    decisions: List[AIValidationDecision] = Field(default_factory=list)
    decisions_by_field: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    rejected_fields: List[str] = Field(default_factory=list)
    downgraded_fields: List[str] = Field(default_factory=list)
    accepted_fields: List[str] = Field(default_factory=list)
    validated_hypotheses: List[Dict[str, Any]] = Field(default_factory=list)
