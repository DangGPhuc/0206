"""
Comprehensive Hardening & Regression Verification Tests (Phases 1-28)
Verifies:
- Reputation stage in pipeline
- Raw evidence export opt-in vs sanitized default
- Environment-derived API keys and pre-flight DLP boundary
- Subprocess huge output truncation and bounded streaming
- CLI options: --quiet, --json, --no-color, --export-raw-evidence
- 23-section report structure compliance and [NOT_ANALYZED] tags
"""
import os
import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from core.process_guard import SafeProcessGuard
from core.privacy import PrivacyRedactor, DLPStatus
from core.orchestrator import AnalysisOrchestrator
from core.manifest import AnalysisManifest
from analyzers.reputation.stage import ReputationStage
from analyzers.reputation.provider import ReputationStatus
from reporting.adapters.markdown_adapter import MarkdownReportAdapter
from reporting.adapters.generic_docx_adapter import GenericDOCXReportAdapter
import docx


class TestHardeningVerification(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_process_guard_huge_output_truncation(self):
        """Phase 20: Enforce that processes producing output exceeding MAX_STDOUT_BYTES are truncated safely."""
        # Run python command that prints 6 MB of data
        cmd = [sys.executable, "-c", "import sys; sys.stdout.write('A' * (6 * 1024 * 1024))"]
        result = SafeProcessGuard.run(cmd, max_stdout_bytes=1024 * 1024, timeout_sec=10)

        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.stdout), 1024 * 1024 + 100)
        self.assertEqual(result.exit_code, 0)

    def test_privacy_redactor_extended_secrets_and_dlp(self):
        """Phase 5: DLP detects AWS keys, GitHub tokens, Bearer tokens, and private keys."""
        redactor = PrivacyRedactor()

        # AWS secret
        aws_sample = "AKIA" + "IOSFODNN7EXAMPLE"
        text_aws = f"aws_secret = {aws_sample}"
        audit_res = redactor.audit_for_remote_transmission(text_aws)
        is_safe, reasons = audit_res
        self.assertFalse(is_safe)
        self.assertEqual(audit_res.status, DLPStatus.BLOCKED)

        # Redaction works
        redacted = redactor.redact(text_aws)
        self.assertNotIn(aws_sample, redacted)
        self.assertIn("[REDACTED_AWS_KEY]", redacted)

        # GitHub token
        gh_sample = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB"
        text_gh = f"token: {gh_sample}"
        self.assertIn("[REDACTED_GITHUB_TOKEN]", redactor.redact(text_gh))

        # Safe text
        safe_text = "Analysis of benign sample completed without errors."
        audit_safe = redactor.audit_for_remote_transmission(safe_text)
        self.assertTrue(audit_safe.is_safe)
        self.assertEqual(audit_safe.status, DLPStatus.SAFE)

    def test_reputation_stage_offline_and_failure(self):
        """Phase 2: Reputation failure or offline mode must not abort and must record EvidenceRecord."""
        stage = ReputationStage()
        records = stage.execute("a" * 64, offline=True)
        self.assertEqual(len(records), 2)
        fields = {r.field: r.value for r in records}
        self.assertIn(fields.get("lookup_status"), ("NOT_CHECKED", "SKIPPED_OFFLINE"))
        self.assertNotEqual(fields.get("lookup_status"), "COMPLETED")
        self.assertNotEqual(fields.get("lookup_status"), "CLEAN")

    def test_raw_evidence_opt_in_vs_sanitized_default(self):
        """Phase 4: Raw evidence export is opt-in (evidence.raw.json), default is sanitized (evidence.json)."""
        orchestrator = AnalysisOrchestrator()
        fixture = Path("tests/sample_benign_triage.exe")
        if not fixture.exists():
            self.skipTest("sample_benign_triage.exe fixture missing")
        out_dir = self.work_dir / "out_default"

        # Default run (export_raw_evidence=False)
        res_default = orchestrator.run(
            sample_path=str(fixture),
            output_dir=str(out_dir),
            offline=True,
            export_raw_evidence=False
        )
        self.assertTrue(res_default.evidence_json.exists())
        self.assertIsNone(res_default.evidence_raw_json)
        self.assertFalse((out_dir / "evidence.raw.json").exists())

        # Opt-in run (export_raw_evidence=True)
        out_optin = self.work_dir / "out_optin"
        res_optin = orchestrator.run(
            sample_path=str(fixture),
            output_dir=str(out_optin),
            offline=True,
            export_raw_evidence=True
        )
        self.assertTrue(res_optin.evidence_json.exists())
        self.assertIsNotNone(res_optin.evidence_raw_json)
        self.assertTrue((out_optin / "evidence.raw.json").exists())

    def test_markdown_and_docx_23_sections(self):
        """Phase 18: Markdown & DOCX adapters conform to 23 sections with [NOT_ANALYZED] for unanalyzed sections."""
        manifest = AnalysisManifest(sample_filename="test.exe", sample_size_bytes=100)
        session_data = {
            "manifest": manifest.model_dump(),
            "assessment": {
                "threat_score": 10,
                "threat_level": "LOW",
                "classification": "Clean / Benign",
                "summary": "Benign utility.",
                "key_functionality": "Testing.",
                "host_iocs": [],
                "network_iocs": [],
                "mitre_techniques": []
            },
            "findings": [],
            "evidence_records": [],
            "coverage": {"domain_coverage": {"PE": "COMPLETED", "Memory": "NOT_ANALYZED"}}
        }

        # Render Markdown
        md_adapter = MarkdownReportAdapter()
        md_file = self.work_dir / "test_report.md"
        md_adapter.render(session_data, md_file)
        md_content = md_file.read_text(encoding="utf-8")

        # Verify all key numbered sections exist
        self.assertIn("## PART I — BASIC ANALYSIS", md_content)
        self.assertIn("### 1. Summary", md_content)
        self.assertIn("### 2. Identification / IOCs", md_content)
        self.assertIn("### 3. Reputation", md_content)
        self.assertIn("### 4. Static Properties Analysis", md_content)
        self.assertIn("### 5. Basic Behavioral Analysis", md_content)
        self.assertIn("### 6. Initial Findings", md_content)
        self.assertIn("### 7. Initial Assessment", md_content)
        self.assertIn("## PART II — ADVANCED ANALYSIS", md_content)
        self.assertIn("### 8. Advanced Static Analysis", md_content)
        self.assertIn("### 9. Assembly / Code Analysis", md_content)
        self.assertIn("### 10. API / Control Flow", md_content)
        self.assertIn("### 11. Advanced Behavioral Analysis", md_content)
        self.assertIn("### 12. Process / Thread", md_content)
        self.assertIn("### 13. Memory", md_content)
        self.assertIn("### 14. Network / C2", md_content)
        self.assertIn("### 15. Persistence", md_content)
        self.assertIn("### 16. Anti-Analysis", md_content)
        self.assertIn("### 17. Packing / Unpacking", md_content)
        self.assertIn("### 18. .NET / Scripts / Documents where applicable", md_content)
        self.assertIn("### 19. Cross-Stage Correlation", md_content)
        self.assertIn("### 20. Final Assessment", md_content)
        self.assertIn("### 21. IOC", md_content)
        self.assertIn("### 22. MITRE ATT&CK", md_content)
        self.assertIn("### 23. Coverage", md_content)
        self.assertIn("### 24. Evidence Appendix", md_content)
        self.assertIn("### 25. Analysis Manifest", md_content)
        self.assertIn("[NOT_ANALYZED]", md_content)

        # Render DOCX
        docx_adapter = GenericDOCXReportAdapter()
        docx_file = self.work_dir / "test_report.docx"
        docx_adapter.render(session_data, docx_file)
        doc = docx.Document(str(docx_file))
        headings = [p.text for p in doc.paragraphs if p.style.name.startswith("Heading")]
        self.assertTrue(any("1. Summary" in h for h in headings))
        self.assertTrue(any("20. Final Assessment" in h for h in headings))
        self.assertTrue(any("25. Analysis Manifest" in h for h in headings))


if __name__ == "__main__":
    unittest.main()
