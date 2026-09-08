"""
Unit tests for external tool adapters and MCP integration contract.
"""
import unittest
from pathlib import Path

from integrations.adapters import ADAPTER_REGISTRY, YaraAdapter, IdaProAdapter, X64DbgAdapter
from integrations.mcp_contract import MCPEvidenceIngester
from core.evidence import EvidenceStore, EvidenceState


class TestAdaptersAndMCP(unittest.TestCase):

    def test_adapter_registry_presence(self):
        self.assertIn("YARA", ADAPTER_REGISTRY)
        self.assertIn("capa", ADAPTER_REGISTRY)
        self.assertIn("Ghidra", ADAPTER_REGISTRY)
        self.assertIn("IDA Pro", ADAPTER_REGISTRY)
        self.assertIn("x64dbg", ADAPTER_REGISTRY)
        self.assertIn("WinDbg", ADAPTER_REGISTRY)

    def test_missing_proprietary_adapter_never_crashes(self):
        # Even if IDA / x64dbg are not installed, analyze() must return NOT_AVAILABLE safely
        ida = IdaProAdapter(config_override="/nonexistent/ida64")
        self.assertFalse(ida.available())
        store = EvidenceStore()
        records = ida.analyze(Path("dummy.exe"), evidence_store=store)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].state, EvidenceState.NOT_AVAILABLE)

    def test_mcp_evidence_ingester(self):
        store = EvidenceStore()
        ingester = MCPEvidenceIngester(store)

        payload = {
            "source_artifact": "sample.exe",
            "source_type": "DECOMPILATION",
            "field": "crypto_constants",
            "value": "RC4 KSA S-box detected at sub_401000",
            "state": "OBSERVED",
            "confidence": 0.95,
            "extractor": "External_MCP_Ghidra",
            "provenance": {"subroutine": "sub_401000"}
        }

        rec = ingester.ingest_record(payload)
        self.assertEqual(rec.source_artifact, "sample.exe")
        self.assertEqual(rec.field, "crypto_constants")
        self.assertEqual(rec.state, EvidenceState.OBSERVED)
        self.assertEqual(len(store), 1)


if __name__ == "__main__":
    unittest.main()
