"""
Unit Tests for 0206 Static PE Analyzer Module
"""
import unittest
import tempfile
from pathlib import Path
from analyzer.static import PEStaticAnalyzer, calculate_shannon_entropy
from core.evidence import EvidenceStore

TESTS_DIR = Path(__file__).resolve().parent


class TestStaticAnalyzer(unittest.TestCase):

    def setUp(self):
        self.sample_pe = TESTS_DIR / "sample_benign_triage.exe"
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_shannon_entropy_calculation(self):
        # Uniform zero bytes -> entropy 0.0
        self.assertEqual(calculate_shannon_entropy(b"\x00" * 100), 0.0)
        # Empty -> 0.0
        self.assertEqual(calculate_shannon_entropy(b""), 0.0)
        # High entropy random-like data
        import os
        random_bytes = os.urandom(1024)
        self.assertGreater(calculate_shannon_entropy(random_bytes), 7.0)

    def test_static_pe_parsing_and_evidence(self):
        if not self.sample_pe.exists():
            self.skipTest("sample_benign_triage.exe fixture missing")

        store = EvidenceStore()
        analyzer = PEStaticAnalyzer(self.sample_pe, evidence_store=store)
        telemetry = analyzer.analyze()

        self.assertTrue(telemetry["file_info"]["is_pe"])
        self.assertEqual(telemetry["file_info"]["architecture"], "64-bit (x64)")
        self.assertGreater(len(telemetry["sections"]), 0)

        # Verify evidence records emitted
        self.assertGreater(len(store), 5)
        sha_evs = store.find(field="sha256")
        self.assertEqual(len(sha_evs), 1)

    def test_corrupted_pe_handling(self):
        corrupt_file = Path(self.temp_dir.name) / "corrupt.exe"
        corrupt_file.write_bytes(b"MZ" + b"\xFF" * 100)

        store = EvidenceStore()
        analyzer = PEStaticAnalyzer(corrupt_file, evidence_store=store)
        telemetry = analyzer.analyze()

        # Should not crash, returns warning
        self.assertFalse(telemetry["file_info"]["is_pe"])
        self.assertGreater(len(telemetry["warnings"]), 0)


if __name__ == "__main__":
    unittest.main()
