"""
Regression and Semantic Consistency Unit Tests
Tests all 10 hardening rules:
1. Canonical coverage model
2. Truthful offline reputation
3. Canonical evidence count consistency (30 vs 29)
4. Classification: UNKNOWN / NOT_ESTABLISHED on 0 findings (no "Suspicious.PE.Generic")
5. Confidence: separate classification vs analysis confidence (no 1.0 on UNKNOWN)
6. Purpose text: NOT_ESTABLISHED on ungrounded baseline
7. Recommendations: conditioned on findings (no quarantine on score 0)
8. Coverage semantics: truthful NOT_ANALYZED (no negative detection claims)
9. Anti-analysis semantics: truthful NOT_ANALYZED
10. CaseSemanticValidator and validate-case integration
"""
import unittest
import tempfile
import json
import hashlib
from pathlib import Path

from core.orchestrator import AnalysisOrchestrator
from core.semantic_validator import CaseSemanticValidator, SemanticValidationResult
from core.assessment import AssessmentEngine
from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from core.schemas import AnalysisDomain, Finding, FindingStatus, FindingCategory, CoverageStatus
from analyzers.reputation.stage import ReputationStage


class TestSemanticValidator(unittest.TestCase):

    def setUp(self):
        self.fixture_exe = Path(__file__).resolve().parent / "sample_benign_triage.exe"
        self.validator = CaseSemanticValidator()

    def test_benign_e2e_case_passes_validation(self):
        """Rule 1-10: A clean basic offline run on benign PE produces a 100% PASS validation result."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            orchestrator = AnalysisOrchestrator()
            result = orchestrator.run(
                sample_path=self.fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_dir
            )
            val_res: SemanticValidationResult = self.validator.validate_case(tmp_dir)
            if not val_res.is_pass():
                fails = [f"{i.rule}: {i.message}" for i in val_res.issues if i.severity == "FAIL"]
                self.fail(f"Validation failed with {len(fails)} errors: {fails}")

            self.assertEqual(val_res.status, "PASS")
            self.assertGreater(val_res.passed_checks, 5)
            self.assertEqual(val_res.failed_checks, 0)

    def test_coverage_consistency_catches_discrepancy(self):
        """Rule 1: Validator detects discrepancy between coverage.json and assessment.json."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            orchestrator = AnalysisOrchestrator()
            orchestrator.run(
                sample_path=self.fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_dir
            )
            # Mutate coverage.json
            cov_path = Path(tmp_dir) / "coverage.json"
            cov = json.loads(cov_path.read_text(encoding="utf-8"))
            cov["domain_coverage"]["PE Static"] = "NOT_ANALYZED"
            cov_path.write_text(json.dumps(cov, indent=2), encoding="utf-8")

            # Update sha256 in companion to isolate test to coverage rule
            val_res = self.validator.validate_case(tmp_dir)
            cov_fails = [i for i in val_res.issues if i.rule == "coverage_consistency" and i.severity == "FAIL"]
            self.assertTrue(len(cov_fails) > 0, "Validator should detect coverage discrepancy")
            self.assertIn("coverage.json='NOT_ANALYZED' vs assessment.json='COMPLETED'", cov_fails[0].message)

    def test_evidence_count_consistency_catches_30_vs_29(self):
        """Rule 3: Validator detects evidence count mismatch between evidence.json and assessment."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            orchestrator = AnalysisOrchestrator()
            orchestrator.run(
                sample_path=self.fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_dir
            )
            ass_path = Path(tmp_dir) / "assessment.json"
            ass = json.loads(ass_path.read_text(encoding="utf-8"))
            # Artificially set 29 while evidence.json has 30
            ass["evidence_graph_nodes"] = 29
            ass_path.write_text(json.dumps(ass, indent=2), encoding="utf-8")

            val_res = self.validator.validate_case(tmp_dir)
            ev_fails = [i for i in val_res.issues if i.rule == "evidence_count_consistency" and i.severity == "FAIL"]
            self.assertTrue(len(ev_fails) > 0, "Validator should catch evidence count discrepancy")

    def test_classification_rejects_legacy_suspicious_pe_generic(self):
        """Rule 4: Validator rejects legacy 'Suspicious.PE.Generic' on benign/empty finding baseline."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            orchestrator = AnalysisOrchestrator()
            orchestrator.run(
                sample_path=self.fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_dir
            )
            ass_path = Path(tmp_dir) / "assessment.json"
            ass = json.loads(ass_path.read_text(encoding="utf-8"))
            ass["classification"] = "Suspicious.PE.Generic"
            ass_path.write_text(json.dumps(ass, indent=2), encoding="utf-8")

            val_res = self.validator.validate_case(tmp_dir)
            class_fails = [i for i in val_res.issues if i.rule == "classification_consistency" and i.severity == "FAIL"]
            self.assertTrue(len(class_fails) > 0)
            self.assertIn("Suspicious.PE.Generic", class_fails[0].message)

    def test_confidence_rejects_1_on_unknown_classification(self):
        """Rule 5: Validator rejects classification_confidence 1.0 when classification is UNKNOWN."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            orchestrator = AnalysisOrchestrator()
            orchestrator.run(
                sample_path=self.fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_dir
            )
            ass_path = Path(tmp_dir) / "assessment.json"
            ass = json.loads(ass_path.read_text(encoding="utf-8"))
            ass["classification"] = "UNKNOWN / NOT_ESTABLISHED"
            ass["classification_confidence"] = 1.0
            ass_path.write_text(json.dumps(ass, indent=2), encoding="utf-8")

            val_res = self.validator.validate_case(tmp_dir)
            conf_fails = [i for i in val_res.issues if i.rule == "classification_consistency" and "confidence cannot be 1.0" in i.message]
            self.assertTrue(len(conf_fails) > 0)

    def test_purpose_rejects_unsupported_generic_payload_text(self):
        """Rule 6: Validator rejects 'Suspicious execution or remote payload deployment' when findings == 0."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            orchestrator = AnalysisOrchestrator()
            orchestrator.run(
                sample_path=self.fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_dir
            )
            ass_path = Path(tmp_dir) / "assessment.json"
            ass = json.loads(ass_path.read_text(encoding="utf-8"))
            ass["classification"] = "UNKNOWN / NOT_ESTABLISHED"
            ass["purpose"] = "Suspicious execution or remote payload deployment."
            ass_path.write_text(json.dumps(ass, indent=2), encoding="utf-8")

            val_res = self.validator.validate_case(tmp_dir)
            p_fails = [i for i in val_res.issues if i.rule == "classification_consistency" and "Unsupported generic purpose text" in i.message]
            self.assertTrue(len(p_fails) > 0)

    def test_recommendations_rejects_quarantine_on_clean_baseline(self):
        """Rule 7: Validator rejects active quarantine/containment recommendations on threat_score == 0."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            orchestrator = AnalysisOrchestrator()
            orchestrator.run(
                sample_path=self.fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_dir
            )
            ass_path = Path(tmp_dir) / "assessment.json"
            ass = json.loads(ass_path.read_text(encoding="utf-8"))
            ass["threat_score"] = 0
            ass["recommendations"].append("Quarantine host immediately and block domain at perimeter firewall.")
            ass_path.write_text(json.dumps(ass, indent=2), encoding="utf-8")

            val_res = self.validator.validate_case(tmp_dir)
            r_fails = [i for i in val_res.issues if i.rule == "score_finding_consistency" and "containment/quarantine" in i.message]
            self.assertTrue(len(r_fails) > 0)

    def test_not_analyzed_semantics_rejects_negative_heuristic_claims(self):
        """Rule 8 & 9: Validator rejects negative detection claims for NOT_ANALYZED domains."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            orchestrator = AnalysisOrchestrator()
            orchestrator.run(
                sample_path=self.fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_dir
            )
            cov_path = Path(tmp_dir) / "coverage.json"
            cov = json.loads(cov_path.read_text(encoding="utf-8"))
            cov["coverage_reasons"]["Unpacking"] = "No packing indicators identified."
            cov_path.write_text(json.dumps(cov, indent=2), encoding="utf-8")

            val_res = self.validator.validate_case(tmp_dir)
            not_fails = [i for i in val_res.issues if i.rule == "not_analyzed_semantics" and i.severity == "FAIL"]
            self.assertTrue(len(not_fails) > 0)
            self.assertIn("reason implies analysis ran", not_fails[0].message)

    def test_offline_reputation_rejects_completed_status(self):
        """Rule 2: Offline reputation must not be marked COMPLETED when no lookup occurred."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            orchestrator = AnalysisOrchestrator()
            orchestrator.run(
                sample_path=self.fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_dir
            )
            cov_path = Path(tmp_dir) / "coverage.json"
            cov = json.loads(cov_path.read_text(encoding="utf-8"))
            cov["domain_coverage"]["Reputation"] = "COMPLETED"
            cov_path.write_text(json.dumps(cov, indent=2), encoding="utf-8")

            val_res = self.validator.validate_case(tmp_dir)
            rep_fails = [i for i in val_res.issues if i.rule == "reputation_semantics" and i.severity == "FAIL"]
            self.assertTrue(len(rep_fails) > 0)

    def test_finding_evidence_references_catches_dangling_ids(self):
        """Rule 10: Validator detects findings referencing non-existent evidence IDs."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            orchestrator = AnalysisOrchestrator()
            orchestrator.run(
                sample_path=self.fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_dir
            )
            findings_path = Path(tmp_dir) / "findings.json"
            findings = [
                {
                    "finding_id": "F-TEST-001",
                    "title": "Dangling Finding",
                    "domain": "PE",
                    "evidence_ids": ["E-NONEXISTENT-9999"]
                }
            ]
            findings_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")

            val_res = self.validator.validate_case(tmp_dir)
            f_fails = [i for i in val_res.issues if i.rule == "finding_evidence_references" and i.severity == "FAIL"]
            self.assertTrue(len(f_fails) > 0)
            self.assertIn("E-NONEXISTENT-9999", f_fails[0].message)

    def test_privacy_leak_detection(self):
        """Rule 10: Validator detects unredacted analyst paths in deliverables."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            orchestrator = AnalysisOrchestrator()
            orchestrator.run(
                sample_path=self.fixture_exe,
                profile="basic",
                offline=True,
                privacy_mode="strict",
                output_dir=tmp_dir
            )
            # Inject raw path into report.md
            md_path = Path(tmp_dir) / "report.md"
            md_content = md_path.read_text(encoding="utf-8")
            md_content += "\nLeaked path: /run/media/kali/New Volume/malware/sample.exe\n"
            md_path.write_text(md_content, encoding="utf-8")

            val_res = self.validator.validate_case(tmp_dir)
            priv_fails = [i for i in val_res.issues if i.rule == "privacy_safe_output" and i.severity == "FAIL"]
            self.assertTrue(len(priv_fails) > 0)


if __name__ == "__main__":
    unittest.main()
