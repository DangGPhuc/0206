"""
Unit Tests for 0206 Multi-format Report Adapters (JSON, Markdown, Generic DOCX)
"""
import unittest
import tempfile
import json
from pathlib import Path
import docx

from report.adapters.json_adapter import JSONReportAdapter
from report.adapters.markdown_adapter import MarkdownReportAdapter
from report.adapters.generic_docx_adapter import GenericDOCXReportAdapter
from core.manifest import AnalysisManifest
from core.findings import Assessment, Finding, FindingCategory


class TestReportAdapters(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

        manifest = AnalysisManifest(sample_filename="test_sample.exe", sample_size_bytes=12345)
        assessment = Assessment(
            assessment_id="A-001",
            title="Triage Assessment",
            threat_level="HIGH",
            threat_score=75,
            classification="Trojan.Downloader",
            summary="Test executive summary.",
            key_functionality="Downloads secondary payload.",
            purpose="Initial foothold.",
            persistence_assessment="None.",
            runtime_confirmation_status="NOT_CONFIRMED",
            mitre_techniques=[{"technique_id": "T1071", "technique_name": "App Layer Protocol", "tactic": "C2", "evidence_ids": ["E-001"]}],
            host_iocs=["SHA256: 1234567890abcdef"],
            network_iocs=["DNS: c2.bad.test"],
            recommendations=["Block domain."]
        )
        finding = Finding(
            finding_id="F-001",
            category=FindingCategory.NETWORK_C2,
            title="Observed C2 Beacon",
            evidence_level="OBSERVED",
            details="Outbound traffic",
            source_evidence_ids=["E-001"]
        )

        self.session_data = {
            "manifest": manifest.model_dump(),
            "assessment": assessment.model_dump(),
            "findings": [finding.model_dump()],
            "evidence_records": [{"evidence_id": "E-001", "field": "dns_query", "value": "c2.bad.test"}]
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_json_adapter(self):
        adapter = JSONReportAdapter()
        out_file = self.output_dir / "report.json"
        adapter.render(self.session_data, out_file)
        self.assertTrue(out_file.exists())
        loaded = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(loaded["assessment"]["threat_level"], "HIGH")

    def test_markdown_adapter(self):
        adapter = MarkdownReportAdapter()
        out_file = self.output_dir / "report.md"
        adapter.render(self.session_data, out_file)
        self.assertTrue(out_file.exists())
        content = out_file.read_text(encoding="utf-8")
        self.assertIn("Trojan.Downloader", content)
        self.assertIn("F-001", content)

    def test_generic_docx_adapter(self):
        adapter = GenericDOCXReportAdapter()
        out_file = self.output_dir / "report.docx"
        adapter.render(self.session_data, out_file)
        self.assertTrue(out_file.exists())
        doc = docx.Document(str(out_file))
        self.assertGreater(len(doc.tables), 0)


if __name__ == "__main__":
    unittest.main()
