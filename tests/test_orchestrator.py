"""
Unit tests for AnalysisOrchestrator and profile execution.
"""
import unittest
import tempfile
from pathlib import Path

from core.orchestrator import AnalysisOrchestrator
from core.profiles import get_profile, ProfileName
from core.evidence import EvidenceStore
from core.manifest import AnalysisManifest


class TestOrchestrator(unittest.TestCase):

    def setUp(self):
        self.orchestrator = AnalysisOrchestrator()
        self.fixture_exe = Path(__file__).parent / "sample_benign_triage.exe"

    def test_minimal_profile_config(self):
        p_min = get_profile("minimal")
        self.assertEqual(p_min.name, ProfileName.MINIMAL)
        self.assertFalse(p_min.enable_behavioral)
        self.assertTrue(p_min.force_offline_ai)

    def test_orchestrator_execution_and_lineage(self):
        if not self.fixture_exe.exists():
            self.skipTest("Sample benign fixture not found")

        with tempfile.TemporaryDirectory() as tmp_dir:
            res = self.orchestrator.run(
                sample_path=self.fixture_exe,
                output_dir=tmp_dir,
                profile="minimal",
                offline=True
            )
            # Verify 6 deliverable files exist
            self.assertTrue(res.report_json.exists())
            self.assertTrue(res.report_md.exists())
            self.assertTrue(res.report_docx.exists())
            self.assertTrue(res.evidence_json.exists())
            self.assertTrue(res.findings_json.exists())
            self.assertTrue(res.manifest_json.exists())

            # Verify lineage recorded in manifest
            lineage = res.manifest.output_lineage
            self.assertIn("report.json", lineage)
            self.assertIn("report.md", lineage)
            self.assertIn("report.docx", lineage)
            self.assertIn("evidence.json", lineage)
            self.assertIn("findings.json", lineage)
            self.assertNotEqual(lineage["report.json"]["sha256"], "N/A")


if __name__ == "__main__":
    unittest.main()
