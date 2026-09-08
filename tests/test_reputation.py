"""
0206 - Reputation Provider Unit Tests
Phase 34: test_reputation.py
"""
import unittest
from analyzers.reputation import (
    ReputationStatus,
    ReputationResult,
    VirusTotalReputationProvider,
)
from core.evidence import EvidenceStore


class TestReputationProvider(unittest.TestCase):

    def test_reputation_statuses(self):
        statuses = [s.value for s in ReputationStatus]
        self.assertIn("KNOWN_MALICIOUS", statuses)
        self.assertIn("KNOWN_SUSPICIOUS", statuses)
        self.assertIn("LOW_DETECTION", statuses)
        self.assertIn("NOT_FOUND", statuses)
        self.assertIn("LOOKUP_FAILED", statuses)
        self.assertIn("NOT_CHECKED", statuses)

    def test_not_found_is_never_clean(self):
        res = ReputationResult(
            provider="VirusTotal",
            query_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status=ReputationStatus.NOT_FOUND,
            detection_count=0,
            total_engines=0
        )
        self.assertEqual(res.status, ReputationStatus.NOT_FOUND)
        self.assertNotEqual(res.status, "CLEAN")

    def test_vt_lookup_without_api_key(self):
        store = EvidenceStore()
        provider = VirusTotalReputationProvider(api_key="")
        result = provider.lookup_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", evidence_store=store)
        self.assertEqual(result.status, ReputationStatus.NOT_CHECKED)
        self.assertIn("API key", result.details)


if __name__ == "__main__":
    unittest.main()
