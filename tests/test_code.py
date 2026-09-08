"""
Unit Tests for 0206 Static Disassembly Module (Capstone)
"""
import unittest
from pathlib import Path
from analyzer.code import CodeAnalyzer, CAPSTONE_AVAILABLE
from core.evidence import EvidenceStore

TESTS_DIR = Path(__file__).resolve().parent


class TestCodeAnalyzer(unittest.TestCase):

    def setUp(self):
        self.sample_pe = TESTS_DIR / "sample_benign_triage.exe"
        self.store = EvidenceStore()

    def test_entry_point_disassembly(self):
        if not self.sample_pe.exists():
            self.skipTest("sample_benign_triage.exe fixture missing")

        analyzer = CodeAnalyzer(self.sample_pe, evidence_store=self.store)
        res = analyzer.analyze(max_instructions=15)

        if CAPSTONE_AVAILABLE:
            self.assertEqual(res["status"], "OBSERVED")
            self.assertEqual(res["architecture"], "x64")
            self.assertGreater(len(res["instructions"]), 0)
        else:
            self.assertEqual(res["status"], "NOT_AVAILABLE")


if __name__ == "__main__":
    unittest.main()
