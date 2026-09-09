"""
Unit Tests for 0206 AI Grounding & Anti-Hallucination Controls
"""
import os
import unittest
from unittest.mock import patch
from core.evidence import EvidenceStore
from core.findings import Finding, FindingCategory, FindingEngine
from ai.agent import LLMThreatSynthesizer


class TestAIGrounding(unittest.TestCase):

    def setUp(self):
        self.store = EvidenceStore()
        # Add authentic evidence
        self.store.create("sample.exe", "FILE_METADATA", "sha256", "REAL_SHA256_HASH_12345678", "PEStaticAnalyzer")
        self.store.create("sample.exe", "PCAP_DNS", "dns_query", {"domain": "real-c2.test", "resolved_ips": ["198.51.100.1"]}, "BehavioralAnalyzer")

    def test_offline_grounding_preserves_authentic_iocs(self):
        engine = FindingEngine(self.store)
        findings = engine.analyze()

        synthesizer = LLMThreatSynthesizer(provider="offline")
        assessment = synthesizer.synthesize(self.store, findings)

        # Assert that host IOC contains the real sha256
        self.assertTrue(any("REAL_SHA256_HASH_12345678" in h for h in assessment.host_iocs))
        # Assert that network IOC contains the real domain
        self.assertTrue(any("real-c2.test" in n for n in assessment.network_iocs))

    def test_provider_specific_default_models(self):
        with patch.dict(
            os.environ,
            {
                "OPENAI_MODEL": "gpt-test-default",
                "ANTHROPIC_MODEL": "claude-test-default",
                "OLLAMA_MODEL": "ollama-test-default",
            },
            clear=True,
        ):
            self.assertEqual(
                LLMThreatSynthesizer(provider="openai").model,
                "gpt-test-default",
            )
            self.assertEqual(
                LLMThreatSynthesizer(provider="anthropic").model,
                "claude-test-default",
            )
            self.assertEqual(
                LLMThreatSynthesizer(provider="ollama").model,
                "ollama-test-default",
            )

    def test_merge_validation_filters_hallucinated_mitre_evidence(self):
        synthesizer = LLMThreatSynthesizer(provider="offline")
        engine = FindingEngine(self.store)
        baseline = engine.generate_assessment()

        # Simulated AI response with one real evidence ID and one hallucinated ID
        ai_dict = {
            "threat_level": "HIGH",
            "threat_score": 85,
            "malware_family": "Trojan.Downloader",
            "executive_summary": "AI interpreted summary.",
            "mitre_attack": [
                {
                    "technique_id": "T1071",
                    "technique_name": "Web Protocols",
                    "tactic": "C2",
                    "evidence_ids": ["E-0002", "E-FAKE-9999"]
                }
            ]
        }

        validated = synthesizer._merge_and_validate(ai_dict, baseline, self.store)
        # E-FAKE-9999 should have been stripped
        t = validated.mitre_techniques[0]
        self.assertIn("E-0002", t["evidence_ids"])
        self.assertNotIn("E-FAKE-9999", t["evidence_ids"])


if __name__ == "__main__":
    unittest.main()
