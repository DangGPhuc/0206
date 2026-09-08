"""
0206 - MCP (Model Context Protocol) Optional Integration Contract
Provides a contract and schema for external MCP servers or tools to submit
evidence records into the 0206 EvidenceStore.

Flow:
  External Tool / MCP Server
          │
          ▼
   MCPEvidenceIngester (Validates schema & provenance)
          │
          ▼
    EvidenceRecord
          │
          ▼
    EvidenceStore

NOTE: MCP is STRICTLY OPTIONAL. 0206 runs 100% offline without any MCP server.
"""
from typing import Dict, Any, List, Optional
from pathlib import Path
from pydantic import BaseModel, Field

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState


class MCPEvidencePayload(BaseModel):
    """Schema for evidence records submitted via MCP tools or external agents."""
    source_artifact: str
    source_type: str  # e.g., "DISASSEMBLY", "DECOMPILATION", "DEBUGGER", "MEMORY"
    field: str
    value: Any
    state: str = "OBSERVED"
    confidence: float = 1.0
    extractor: str = "MCP_External_Tool"
    extractor_version: str = "1.0.0"
    provenance: Dict[str, Any] = Field(default_factory=dict)
    source_record_id: Optional[str] = None
    source_offset: Optional[int] = None
    source_line: Optional[int] = None


class MCPEvidenceIngester:
    """
    Ingests, validates, and normalizes evidence supplied by external MCP tools.
    """

    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store

    def ingest_record(self, raw_payload: Dict[str, Any]) -> EvidenceRecord:
        """Validates and adds a single MCP evidence payload into the EvidenceStore."""
        validated = MCPEvidencePayload(**raw_payload)
        
        # Normalize state
        try:
            state_enum = EvidenceState(validated.state.upper())
        except Exception:
            state_enum = EvidenceState.OBSERVED

        rec = self.evidence_store.create(
            source_artifact=validated.source_artifact,
            source_type=validated.source_type,
            field=validated.field,
            value=validated.value,
            extractor=validated.extractor,
            state=state_enum,
            confidence=validated.confidence,
            provenance=validated.provenance,
            source_record_id=validated.source_record_id,
            source_offset=validated.source_offset,
            source_line=validated.source_line
        )
        return rec

    def ingest_batch(self, payloads: List[Dict[str, Any]]) -> List[EvidenceRecord]:
        """Validates and ingests a batch of MCP evidence items."""
        return [self.ingest_record(p) for p in payloads]
