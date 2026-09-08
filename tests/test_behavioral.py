"""
Unit Tests for 0206 Behavioral Ingestion & Event Normalization
"""
import unittest
from pathlib import Path
from analyzer.behavioral import BehavioralAnalyzer
from core.evidence import EvidenceStore

TESTS_DIR = Path(__file__).resolve().parent


class TestBehavioralAnalyzer(unittest.TestCase):

    def setUp(self):
        self.procmon_path = TESTS_DIR / "sample_procmon.csv"
        self.store = EvidenceStore()

    def test_procmon_event_normalization(self):
        if not self.procmon_path.exists():
            self.skipTest("sample_procmon.csv fixture missing")

        analyzer = BehavioralAnalyzer(procmon_path=self.procmon_path, evidence_store=self.store)
        res = analyzer.parse_procmon_csv()

        self.assertEqual(res["status"], "OBSERVED")
        self.assertGreater(len(res["normalized_events"]), 0)

        # Check dropped file
        self.assertGreater(len(res["dropped_files"]), 0)
        self.assertIn("dropped_payload.exe", res["dropped_files"][0]["path"])

        # Check registry persistence
        self.assertGreater(len(res["persistence_registry"]), 0)
        self.assertIn("WinSecurityUpdate", res["persistence_registry"][1]["key_path"])

        # Check evidence store
        drop_evs = self.store.find(field="dropped_file")
        self.assertGreaterEqual(len(drop_evs), 1)


if __name__ == "__main__":
    unittest.main()
