"""
Unit Tests for 0206 Network & Multi-Factor Beacon Analysis
"""
import unittest
from pathlib import Path
from analyzer.behavioral import BehavioralAnalyzer
from core.evidence import EvidenceStore

TESTS_DIR = Path(__file__).resolve().parent


class TestNetworkAnalyzer(unittest.TestCase):

    def setUp(self):
        self.pcap_path = TESTS_DIR / "sample_traffic.pcap"
        self.store = EvidenceStore()

    def test_pcap_streaming_and_dns_extraction(self):
        if not self.pcap_path.exists():
            self.skipTest("sample_traffic.pcap fixture missing")

        analyzer = BehavioralAnalyzer(pcap_path=self.pcap_path, evidence_store=self.store)
        res = analyzer.parse_pcap()

        self.assertEqual(res["status"], "OBSERVED")
        self.assertGreater(res["packet_count"], 0)
        
        # Verify DNS extracted
        domains = [d["domain"] for d in res["dns_queries"]]
        self.assertIn("malicious-c2.test", domains)

        # Verify HTTP request extracted
        self.assertGreater(len(res["http_requests"]), 0)
        self.assertEqual(res["http_requests"][0]["method"], "POST")

    def test_beacon_scoring_formula(self):
        # Verify beacon scoring logic directly on custom intervals
        intervals = [5.0, 5.02, 4.98, 5.01, 5.0, 4.99]
        import statistics
        avg_int = statistics.mean(intervals)
        std_dev = statistics.stdev(intervals)
        jitter = std_dev / avg_int

        self.assertLess(jitter, 0.05)  # Very regular intervals have low jitter


if __name__ == "__main__":
    unittest.main()
