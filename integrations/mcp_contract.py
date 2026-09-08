"""
0206 - MCP (Model Context Protocol) Optional Integration Contract
Backward compatibility shim. Canonical implementation lives in `integrations.mcp`.
"""
from integrations.mcp.adapter import MCPEvidencePayload, MCPEvidenceIngester, McpAdapter

__all__ = ["MCPEvidencePayload", "MCPEvidenceIngester", "McpAdapter"]
