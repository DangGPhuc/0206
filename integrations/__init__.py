"""
0206 - Integrations Package Initialization
Phase 13, 14, 15: Optional Tool Integrations & MCP.
"""
from integrations.base import AnalyzerAdapter, AdapterStatus, AdapterResult, GeneratedArtifact
from integrations.registry import CapabilityRegistry
from integrations.adapters import ADAPTER_REGISTRY
from integrations.mcp import MCPEvidencePayload, MCPEvidenceIngester, McpAdapter

__all__ = [
    "AnalyzerAdapter",
    "AdapterStatus",
    "AdapterResult",
    "GeneratedArtifact",
    "CapabilityRegistry",
    "ADAPTER_REGISTRY",
    "MCPEvidencePayload",
    "MCPEvidenceIngester",
    "McpAdapter",
]
