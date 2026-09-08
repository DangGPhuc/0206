"""
0206 - Canonical Evidence Data Model
Defines atomic, verifiable evidence items extracted from static and dynamic analysis.
Preserves granular source location, offsets, lines, and packet numbers.
"""
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
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
    Evidence does not assert conclusions—it records verified facts with location provenance.
    """
    evidence_id: str
    source_artifact: str
    artifact_sha256: Optional[str] = None
    source_type: str  # e.g. PE_HEADER, PE_SECTION, PE_IMPORT, PCAP_DNS, PROCMON_FILE, DISASSEMBLY
    field: str        # e.g. sha256, imported_function, section_entropy, dns_lookup
    value: Any
    state: EvidenceState = EvidenceState.OBSERVED
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    extractor: str
    extractor_version: str = "2.0.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: Dict[str, Any] = Field(default_factory=dict)

    # Granular source location tracking
    source_record_id: Optional[str] = None
    source_offset: Optional[str] = None
    source_line: Optional[int] = None
    source_packet_number: Optional[int] = None
    source_timestamp: Optional[str] = None

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
        prefix: str = "E",
        artifact_sha256: Optional[str] = None,
        source_record_id: Optional[str] = None,
        source_offset: Optional[str] = None,
        source_line: Optional[int] = None,
        source_packet_number: Optional[int] = None,
        source_timestamp: Optional[str] = None
    ) -> EvidenceRecord:
        """Helper to create, register, and return a new EvidenceRecord."""
        evidence_id = f"{prefix}-{self._counter:04d}"
        self._counter += 1

        prov = provenance or {}
        # Auto-populate granular provenance if passed inside prov dictionary
        s_offset = source_offset or prov.get("offset") or prov.get("address")
        s_pkt = source_packet_number or prov.get("packet_index") or prov.get("packet_num")
        s_line = source_line or prov.get("row_index") or prov.get("line_num")
        s_rec_id = source_record_id or prov.get("event_id")

        rec = EvidenceRecord(
            evidence_id=evidence_id,
            source_artifact=source_artifact,
            artifact_sha256=artifact_sha256,
            source_type=source_type,
            field=field,
            value=value,
            state=state,
            confidence=confidence,
            extractor=extractor,
            provenance=prov,
            source_record_id=s_rec_id,
            source_offset=str(s_offset) if s_offset is not None else None,
            source_line=s_line,
            source_packet_number=s_pkt,
            source_timestamp=source_timestamp
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

    def all(self) -> List[EvidenceRecord]:
        """Returns all records in order of creation."""
        return list(self._records.values())

    def all_records(self) -> List[EvidenceRecord]:
        """Alias for all()."""
        return self.all()

    def to_dict(self) -> List[Dict[str, Any]]:
        """Serializes all records to a list of dicts."""
        return [r.model_dump() for r in self._records.values()]

    def to_json(self) -> str:
        """Serializes all records to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def export(self, output_path: Path) -> Path:
        """Exports evidence records to evidence.json."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        return output_path

    def hash(self) -> str:
        """Calculates deterministic SHA256 of all sorted evidence records."""
        serialized = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def __len__(self) -> int:
        return len(self._records)
