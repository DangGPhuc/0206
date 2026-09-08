"""
Unit Tests for 0206 Findings & Evidence Grounding Layer
"""
import unittest
from core.evidence import EvidenceStore, EvidenceState
from core.findings import FindingEngine, FindingCategory, Finding
from core.validators import validate_finding_evidence_grounding


class TestFindingsAndEvidence(unittest.TestCase):

    def setUp(self):
        self.store = EvidenceStore()

    def test_evidence_store_crud(self):
        e1 = self.store.create("sample.exe", "PE_HEADER", "sha256", "abcd1234"*8, "PEStaticAnalyzer")
        self.assertEqual(e1.evidence_id, "E-0001")
        self.assertEqual(len(self.store), 1)

        retrieved = self.store.get("E-0001")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.field, "sha256")

        found = self.store.find(field="sha256")
        self.assertEqual(len(found), 1)

    def test_finding_engine_correlation(self):
        # Register evidence indicating process injection and persistence
        self.store.create("sample.exe", "PE_SECTION", "section_is_rwx", True, "PEStaticAnalyzer", provenance={"section_name": ".text"})
        self.store.create("sample.exe", "PE_IMPORT", "imported_api_injection", "VirtualAllocEx", "PEStaticAnalyzer")
        self.store.create("procmon.csv", "PROCMON_REG", "registry_persistence", {"key_path": "HKCU\\...\\Run"}, "BehavioralAnalyzer")

        engine = FindingEngine(self.store)
        findings = engine.analyze()
        self.assertGreaterEqual(len(findings), 3)

        # Check categories
        cats = [f.category for f in findings]
        self.assertIn(FindingCategory.PACKING_AND_OBFUSCATION, cats)
        self.assertIn(FindingCategory.PROCESS_INJECTION, cats)
        self.assertIn(FindingCategory.PERSISTENCE, cats)

        # Generate assessment
        assessment = engine.generate_assessment()
        self.assertIn("Backdoor", assessment.classification)
        self.assertGreaterEqual(assessment.threat_score, 60)

    def test_validation_of_grounding_evidence(self):
        # Create a finding with a bogus non-existent evidence ID
        f = Finding(
            finding_id="F-9999",
            category=FindingCategory.NETWORK_C2,
            title="Bogus C2 finding",
            evidence_level=EvidenceState.INFERRED,
            details="Fabricated finding without evidence",
            source_evidence_ids=["E-NONEXISTENT-999"]
        )
        validated, warnings = validate_finding_evidence_grounding([f], self.store)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(len(validated[0].source_evidence_ids), 0)
        self.assertLessEqual(validated[0].confidence, 0.3)


if __name__ == "__main__":
    unittest.main()
