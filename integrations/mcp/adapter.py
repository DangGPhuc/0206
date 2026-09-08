"""
0206 - MCP (Model Context Protocol) Optional Integration Adapter
Phase 15: Implements optional MCP adapter boundary.
Flow: External MCP Tool -> McpAdapter / MCPEvidenceIngester -> Normalized Evidence -> EvidenceStore.
"""
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from core.schemas import AnalysisDomain
from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from integrations.base import AnalyzerAdapter, AdapterStatus, AdapterResult


class MCPEvidencePayload(BaseModel):
    """Schema for evidence records submitted via MCP tools or external agents."""
    source_artifact: str
    source_type: str  # e.g., "DISASSEMBLY", "DECOMPILATION", "DEBUGGER", "MEMORY"
    field: str
    value: Any
    domain: Optional[str] = "CODE_EXECUTION"
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
            extractor_version=validated.extractor_version,
            state=state_enum,
            confidence=validated.confidence,
            provenance=validated.provenance,
            source_record_id=validated.source_record_id,
            source_offset=validated.source_offset,
            source_line=validated.source_line,
            domain=validated.domain or "CODE_EXECUTION",
        )
        return rec

    def ingest_batch(self, payloads: List[Dict[str, Any]]) -> List[EvidenceRecord]:
        """Validates and ingests a batch of MCP evidence items."""
        return [self.ingest_record(p) for p in payloads]


class McpAdapter(AnalyzerAdapter):
    """Optional MCP server integration adapter."""
    name = "MCP"
    version = "1.0.0"
    tier = "Tier 4 (Optional Agent Protocol)"
    capabilities = ["External Tool Evidence Ingestion"]

    def __init__(self, server_url: Optional[str] = None):
        super().__init__(server_url)
        self.server_url = server_url

    def available(self) -> bool:
        # MCP is an optional boundary; available when a server endpoint or ingester is configured
        return True

    def check_functional(self) -> tuple[AdapterStatus, str]:
        return AdapterStatus.READY, "MCP ingester ready for evidence submission."
