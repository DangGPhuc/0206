"""
0206 - Canonical Evidence Data Model
Defines atomic, verifiable evidence items extracted from static and dynamic analysis.
"""
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class EvidenceState(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    NOT_ANALYZED = "NOT_ANALYZED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class EvidenceRecord(BaseModel):
    """
    Atomic piece of raw forensic evidence grounded directly in a source artifact.
    Evidence does not assert conclusions—it records facts.
    """
    evidence_id: str
    source_artifact: str
    source_type: str  # e.g. PE_HEADER, PE_SECTION, PE_IMPORT, PCAP_DNS, PROCMON_FILE
    field: str        # e.g. sha256, imported_function, section_entropy, dns_lookup
    value: Any
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    extractor: str
    extractor_version: str = "2.0.0"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    state: EvidenceState = EvidenceState.OBSERVED

    class Config:
        use_enum_values = True


class EvidenceStore:
    """In-memory registry and query interface for all collected evidence records."""

    def __init__(self):
        self._records: Dict[str, EvidenceRecord] = {}
        self._counter: int = 1

    def create(
        self,
        source_artifact: str,
        source_type: str,
        field: str,
        value: Any,
        extractor: str,
        confidence: float = 1.0,
        provenance: Optional[Dict[str, Any]] = None,
        state: EvidenceState = EvidenceState.OBSERVED,
        prefix: str = "E"
    ) -> EvidenceRecord:
        """Helper to create, register, and return a new EvidenceRecord."""
        evidence_id = f"{prefix}-{self._counter:04d}"
        self._counter += 1

        rec = EvidenceRecord(
            evidence_id=evidence_id,
            source_artifact=source_artifact,
            source_type=source_type,
            field=field,
            value=value,
            extractor=extractor,
            confidence=confidence,
            provenance=provenance or {},
            state=state
        )
        self._records[evidence_id] = rec
        return rec

    def add(self, record: EvidenceRecord) -> EvidenceRecord:
        """Adds an existing EvidenceRecord to the store."""
        self._records[record.evidence_id] = record
        return record

    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Retrieves an evidence record by ID."""
        return self._records.get(evidence_id)

    def find(
        self,
        field: Optional[str] = None,
        source_type: Optional[str] = None,
        source_artifact: Optional[str] = None
    ) -> List[EvidenceRecord]:
        """Finds evidence records matching filter criteria."""
        results = []
        for r in self._records.values():
            if field and r.field != field:
                continue
            if source_type and r.source_type != source_type:
                continue
            if source_artifact and r.source_artifact != source_artifact:
                continue
            results.append(r)
        return results

    def all_records(self) -> List[EvidenceRecord]:
        """Returns all records in order of creation."""
        return list(self._records.values())

    def to_dict(self) -> List[Dict[str, Any]]:
        """Serializes all records to a list of dicts."""
        return [r.model_dump() for r in self._records.values()]

    def __len__(self) -> int:
        return len(self._records)
