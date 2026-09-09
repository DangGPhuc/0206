"""
Unit Tests for AI Suggestion Validation Engine (P1.11)
Validates:
- Unknown evidence IDs => REJECT
- Valid evidence IDs => ACCEPT
- Unsupported malware-family claim => DOWNGRADE to heuristic hypothesis
- Threat score override attempt => REJECT (FindingEngine is authoritative)
"""
import unittest
from core.evidence import EvidenceStore
from core.findings import FindingEngine
from ai.agent import LLMThreatSynthesizer, AIFieldStatus


class TestAIValidation(unittest.TestCase):

    def setUp(self):
        self.store = EvidenceStore()
        # Create authentic ground truth evidence
        self.rec1 = self.store.create("sample.exe", "FILE_METADATA", "sha256", "REAL_HASH_1234", "PEStaticAnalyzer")
        self.rec2 = self.store.create("sample.exe", "PE_IMPORT", "import", "VirtualAllocEx", "PEStaticAnalyzer")

        self.synthesizer = LLMThreatSynthesizer(provider="offline")
        engine = FindingEngine(self.store)
        self.baseline = engine.generate_assessment()

    def test_unknown_evidence_ids_rejected(self):
        """AI proposals citing fictitious or ungrounded evidence IDs must be rejected."""
        ai_proposal = {
            "mitre_attack": [
                {
                    "technique_id": "T1055",
                    "technique_name": "Process Injection",
                    "tactic": "Defense Evasion",
                    "evidence_ids": ["E-FAKE-ID-99999", "E-DOES-NOT-EXIST"]
                }
            ]
        }

        validated = self.synthesizer._merge_and_validate(ai_proposal, self.baseline, self.store)
        self.assertIsNotNone(validated.ai_validation)
        val_meta = validated.ai_validation
        self.assertIn("mitre_technique_T1055", val_meta.get("rejected_fields", []))

        # Technique must NOT be in validated mitre_techniques
        added_techniques = [t for t in validated.mitre_techniques if t.get("technique_id") == "T1055"]
        self.assertEqual(len(added_techniques), 0)

    def test_valid_evidence_ids_accepted(self):
        """AI proposals citing authentic, verified Evidence IDs must be accepted."""
        ai_proposal = {
            "mitre_attack": [
                {
                    "technique_id": "T1055.001",
                    "technique_name": "Dynamic-link Library Injection",
                    "tactic": "Defense Evasion",
                    "evidence_ids": [self.rec2.evidence_id]
                }
            ]
        }

        validated = self.synthesizer._merge_and_validate(ai_proposal, self.baseline, self.store)
        val_meta = validated.ai_validation
        self.assertIn("mitre_technique_T1055.001", val_meta.get("accepted_fields", []))

        # Technique must be present with the cited evidence ID
        added_techniques = [t for t in validated.mitre_techniques if t.get("technique_id") == "T1055.001"]
        self.assertEqual(len(added_techniques), 1)
        self.assertEqual(added_techniques[0]["evidence_ids"], [self.rec2.evidence_id])

    def test_unsupported_malware_family_downgraded(self):
        """Unsupported malware family claims must be downgraded to unconfirmed hypothesis."""
        ai_proposal = {
            "malware_family": "Emotet.Banker.v4",
            "classification": "Emotet.Banker.v4"
        }

        validated = self.synthesizer._merge_and_validate(ai_proposal, self.baseline, self.store)
        val_meta = validated.ai_validation
        self.assertIn("malware_family", val_meta.get("downgraded_fields", []))

        # Classification must maintain structured hypothesis without string concatenation
        self.assertIsNotNone(validated.classification_details)
        self.assertEqual(validated.classification_details.hypothesis, "Emotet.Banker.v4")
        self.assertEqual(validated.classification_details.hypothesis_status, "UNCONFIRMED")
        self.assertNotIn("Emotet", validated.classification)

    def test_threat_score_override_rejected(self):
        """AI cannot override deterministic threat score or threat level."""
        ai_proposal = {
            "threat_score": 99,
            "threat_level": "CRITICAL"
        }

        validated = self.synthesizer._merge_and_validate(ai_proposal, self.baseline, self.store)
        val_meta = validated.ai_validation
        self.assertIn("threat_score", val_meta.get("rejected_fields", []))
        self.assertIn("threat_level", val_meta.get("rejected_fields", []))

        # Deterministic authority preserved
        self.assertEqual(validated.threat_score, self.baseline.threat_score)
        self.assertEqual(validated.threat_level, self.baseline.threat_level)


    def test_semantic_evidence_relevance_validation(self):
        """A SHA256 evidence record must not be accepted as support for Process Injection (T1055)."""
        sha256_rec = self.store.find(field="sha256")[0]
        ai_proposal = {
            "mitre_attack": [
                {
                    "technique_id": "T1055",
                    "technique_name": "Process Injection",
                    "tactic": "Defense Evasion",
                    "evidence_ids": [sha256_rec.evidence_id]
                }
            ]
        }
        validated = self.synthesizer._merge_and_validate(ai_proposal, self.baseline, self.store)
        val_meta = validated.ai_validation
        # Technique citing only SHA256 must be rejected for Process Injection
        self.assertIn("mitre_technique_T1055", val_meta.get("rejected_fields", []))
        t1055_techniques = [t for t in validated.mitre_techniques if t.get("technique_id") == "T1055"]
        self.assertEqual(len(t1055_techniques), 0)

    def test_unsupported_narrative_claims_rejected_on_clean_sample(self):
        """AI narrative claiming confirmed injection or C2 on a clean sample must be rejected."""
        ai_proposal = {
            "executive_summary": "Confirmed malicious C2 communication established with host injection."
        }
        validated = self.synthesizer._merge_and_validate(ai_proposal, self.baseline, self.store)
        val_meta = validated.ai_validation
        self.assertIn("executive_summary", val_meta.get("rejected_fields", []))
        self.assertEqual(validated.summary, self.baseline.summary)

    def test_containment_recommendations_rejected_on_zero_score(self):
        """Containment actions (firewall block, quarantine) must be rejected when findings and score are 0."""
        ai_proposal = {
            "incident_recommendations": [
                "Block perimeter firewall and isolate host immediately.",
                "Quarantine affected systems."
            ]
        }
        validated = self.synthesizer._merge_and_validate(ai_proposal, self.baseline, self.store)
        val_meta = validated.ai_validation
        self.assertIn("recommendations", val_meta.get("rejected_fields", []))
        self.assertEqual(validated.recommendations, self.baseline.recommendations)

    def test_structured_classification_fields(self):
        """Ensure Classification model adheres strictly to value, confidence, status, basis, hypothesis, hypothesis_status."""
        ai_proposal = {
            "malware_family": "LockBit"
        }
        validated = self.synthesizer._merge_and_validate(ai_proposal, self.baseline, self.store)
        c = validated.classification_details
        self.assertIsNotNone(c)
        self.assertEqual(c.hypothesis, "LockBit")
        self.assertEqual(c.hypothesis_status, "UNCONFIRMED")
        self.assertEqual(c.value, self.baseline.classification)
        self.assertIn("value", c.model_dump())
        self.assertIn("confidence", c.model_dump())
        self.assertIn("status", c.model_dump())
        self.assertIn("basis", c.model_dump())
        self.assertIn("hypothesis", c.model_dump())
        self.assertIn("hypothesis_status", c.model_dump())


if __name__ == "__main__":
    unittest.main()
