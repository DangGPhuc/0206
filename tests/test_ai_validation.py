"""
0206 - AI Validation Unit Tests
Phase 34: test_ai_validation.py
"""
import unittest
from core.schemas import EvidenceState, AnalysisDomain
from core.evidence import EvidenceStore
from core.findings import Finding, Assessment
from ai.grounding.validator import GroundingValidator
from ai.validation.schema import AIFieldStatus


class TestAIValidation(unittest.TestCase):

    def setUp(self):
        self.store = EvidenceStore()
        self.e1 = self.store.create("sample.exe", "IMPORT", "func", "VirtualAlloc", "PEParser", domain=AnalysisDomain.API)
        self.baseline = Assessment(
            assessment_id="A-0001",
            title="Baseline Assessment",
            threat_level="MEDIUM",
            threat_score=45,
            classification="Generic",
            summary="Deterministic baseline summary"
        )
        self.validator = GroundingValidator(self.store)

    def test_rejection_of_threat_score_override(self):
        ai_proposal = {
            "threat_score": 99,
            "threat_level": "CRITICAL"
        }
        merged, val_result = self.validator.validate_synthesis(ai_proposal, self.baseline)
        self.assertEqual(merged.threat_score, 45)
        self.assertEqual(merged.threat_level, "MEDIUM")
        self.assertIn("threat_score", val_result.rejected_fields)
        self.assertIn("threat_level", val_result.rejected_fields)

    def test_rejection_of_hallucinated_mitre_technique(self):
        ai_proposal = {
            "mitre_attack": [
                {
                    "technique_id": "T1055",
                    "technique_name": "Process Injection",
                    "tactic": "Defense Evasion",
                    "evidence_ids": ["E-9999_NON_EXISTENT"]
                }
            ]
        }
        merged, val_result = self.validator.validate_synthesis(ai_proposal, self.baseline)
        self.assertEqual(len(merged.mitre_techniques), 0)
        self.assertIn("mitre_technique_T1055", val_result.rejected_fields)

    def test_acceptance_of_grounded_mitre_technique(self):
        ai_proposal = {
            "mitre_attack": [
                {
                    "technique_id": "T1106",
                    "technique_name": "Native API",
                    "tactic": "Execution",
                    "evidence_ids": [self.e1.evidence_id]
                }
            ]
        }
        merged, val_result = self.validator.validate_synthesis(ai_proposal, self.baseline)
        self.assertEqual(len(merged.mitre_techniques), 1)
        self.assertIn("mitre_technique_T1106", val_result.accepted_fields)


if __name__ == "__main__":
    unittest.main()
