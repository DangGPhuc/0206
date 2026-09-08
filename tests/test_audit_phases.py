"""
0206 - Comprehensive Phase 23 Architectural Audit & Validation Tests
Validates all 24 phases with benign fixtures and simulated conditions.
Zero malware execution.
"""
import unittest
import tempfile
import json
import hashlib
from pathlib import Path

from core.evidence import EvidenceStore, MemoryEvidenceBackend, SQLiteEvidenceBackend, EvidenceState
from core.findings import FindingEngine, Finding, FindingCategory, Classification, ScoreContribution
from core.manifest import AnalysisManifest
from core.privacy import PrivacyMode, PrivacyRedactor, BLOCK_REMOTE_TRANSMISSION
from core.process_guard import safe_run_process
from ai.agent import LLMThreatSynthesizer, AIFieldStatus
from integrations.base import AdapterStatus, AdapterResult
from integrations.adapters.yara_adapter import YaraAdapter
from integrations.adapters.ghidra_adapter import GhidraAdapter
from integrations.adapters.ida_adapter import IdaProAdapter
from integrations.adapters.x64dbg_adapter import X64DbgAdapter
from analyzer.behavioral import BehavioralAnalyzer
from config import MAX_TRACKED_CONNECTIONS, MAX_TIMESTAMPS_PER_CONNECTION


class TestAuditPhases(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.temp_dir.name)
        # Create a benign test fixture
        self.benign_file = self.tmp_path / "benign.bin"
        self.benign_file.write_bytes(b"MZ" + b"\x90" * 200 + b"BENIGN_TEST_PAYLOAD")

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------
    # 1. AI Validation Authority Reduction (Phase 3)
    # -------------------------------------------------------------
    def test_ai_validation_cannot_override_score_or_confirm_family(self):
        store = EvidenceStore()
        store.create("sample.exe", "PE_HEADER", "is_pe", True, "TestExtractor")
        engine = FindingEngine(store)
        findings = engine.analyze()
        baseline = engine.assess(findings)

        synthesizer = LLMThreatSynthesizer(provider="offline")
        # Simulated rogue AI payload attempting to override score and claim confirmed family
        fake_ai_output = {
            "threat_score": 99,
            "threat_level": "CRITICAL",
            "classification": "Confirmed LockBit 3.0 Ransomware",
            "mitre_techniques": [
                {"technique_id": "T1486", "evidence_ids": ["E-9999"]}  # Non-existent evidence ID
            ]
        }

        validated = synthesizer._merge_and_validate(fake_ai_output, baseline, store)
        
        # Threat score must NOT be overridden
        self.assertEqual(validated.threat_score, baseline.threat_score)
        self.assertEqual(validated.threat_level, baseline.threat_level)

        # AI validation report must be present
        ai_val = validated.ai_validation
        self.assertIsNotNone(ai_val)
        self.assertIn("threat_score", ai_val["rejected_fields"])
        self.assertEqual(ai_val["decisions_by_field"]["threat_score"]["status"], AIFieldStatus.REJECTED.value)
        self.assertIn("malware_family", ai_val["downgraded_fields"])
        self.assertEqual(ai_val["decisions_by_field"]["malware_family"]["status"], AIFieldStatus.DOWNGRADED.value)
        # Non-existent evidence ID must cause MITRE technique rejection
        self.assertEqual(ai_val["decisions_by_field"]["mitre_technique_T1486"]["status"], AIFieldStatus.REJECTED.value)

    # -------------------------------------------------------------
    # 2. Deterministic Score Breakdown (Phase 4)
    # -------------------------------------------------------------
    def test_deterministic_score_breakdown(self):
        store = EvidenceStore()
        store.create("sample.exe", "PE_SECTION", "section_is_rwx", True, "TestExtractor", state=EvidenceState.OBSERVED, provenance={"section_name": ".text"})
        store.create("sample.exe", "IMPORT", "imported_api_injection", "VirtualAllocEx", "TestExtractor", state=EvidenceState.INFERRED)
        
        engine = FindingEngine(store)
        findings = engine.analyze()
        assessment = engine.assess(findings)

        self.assertIsInstance(assessment.score_breakdown, list)
        self.assertGreater(len(assessment.score_breakdown), 0)
        for b in assessment.score_breakdown:
            self.assertTrue(hasattr(b, "finding_id"))
            self.assertTrue(hasattr(b, "base_weight"))
            self.assertTrue(hasattr(b, "confidence"))
            self.assertTrue(hasattr(b, "evidence_strength"))
            self.assertTrue(hasattr(b, "contribution"))
            self.assertGreater(b.contribution, 0.0)


    # -------------------------------------------------------------
    # 3. Manifest Hashing & Integrity Fix (Phase 6)
    # -------------------------------------------------------------
    def test_manifest_no_self_hashing_and_companion_sha256(self):
        manifest = AnalysisManifest()
        manifest_path = self.tmp_path / "analysis_manifest.json"
        
        # Recording output artifact must not include itself
        manifest.record_output_artifact("analysis_manifest.json", manifest_path)
        self.assertNotIn("analysis_manifest.json", manifest.output_lineage)

        # Companion sha256 generation
        sha256_path = manifest.export_json(manifest_path)
        self.assertTrue(manifest_path.exists())
        self.assertTrue(sha256_path.exists())

        # Verify companion sha256 matches the file content
        content = manifest_path.read_text(encoding="utf-8")
        computed = hashlib.sha256(content.encode("utf-8")).hexdigest()
        companion_content = sha256_path.read_text(encoding="utf-8")
        self.assertIn(computed, companion_content)

    # -------------------------------------------------------------
    # 4. Adapter Statuses (Phase 7)
    # -------------------------------------------------------------
    def test_adapter_statuses_enum(self):
        expected_statuses = {"DETECTED", "READY", "FUNCTIONAL", "FAILED", "NOT_INSTALLED", "NOT_SUPPORTED"}
        actual_statuses = {s.value for s in AdapterStatus}
        self.assertEqual(expected_statuses, actual_statuses)

    # -------------------------------------------------------------
    # 5. Missing External Tools (Phase 8 & 11)
    # -------------------------------------------------------------
    def test_missing_external_tools_graceful(self):
        # Point to non-existent binaries
        ghidra = GhidraAdapter(config_override="/nonexistent/ghidra")
        self.assertFalse(ghidra.available())
        st, reason = ghidra.check_functional()
        self.assertEqual(st, AdapterStatus.NOT_INSTALLED)

        ida = IdaProAdapter(config_override="/nonexistent/ida64")
        self.assertFalse(ida.available())
        st, reason = ida.check_functional()
        self.assertEqual(st, AdapterStatus.NOT_INSTALLED)

        store = EvidenceStore()
        res = ida.execute(self.benign_file, evidence_store=store)
        self.assertEqual(res.status, AdapterStatus.NOT_INSTALLED)
        self.assertEqual(len(res.evidence_ids), 0)

    # -------------------------------------------------------------
    # 6. YARA without rules vs with harmless test rule (Phase 9)
    # -------------------------------------------------------------
    def test_yara_without_rules_and_with_rules(self):
        # YARA without rules
        yara_no_rules = YaraAdapter(rules_path=None)
        if yara_no_rules.available():
            st, reason = yara_no_rules.check_functional()
            self.assertEqual(st, AdapterStatus.READY)
            self.assertIn("no rule set provided", reason)

            store = EvidenceStore()
            records = yara_no_rules.analyze(self.benign_file, evidence_store=store)
            self.assertEqual(records[0].state, EvidenceState.NOT_ANALYZED)

        # YARA with harmless test rule
        rule_file = self.tmp_path / "test.yar"
        rule_file.write_text('rule TestRule { strings: $a = "BENIGN" condition: $a }', encoding="utf-8")
        yara_with_rules = YaraAdapter(rules_path=rule_file)
        if yara_with_rules.available():
            st, reason = yara_with_rules.check_functional()
            self.assertEqual(st, AdapterStatus.FUNCTIONAL)

            store = EvidenceStore()
            records = yara_with_rules.analyze(self.benign_file, evidence_store=store)
            matched = [r for r in records if r.field == "rule_match"]
            self.assertEqual(len(matched), 1)
            self.assertEqual(matched[0].state, EvidenceState.OBSERVED)

    # -------------------------------------------------------------
    # 7. Privacy DLP & Remote Transmission Boundary (Phase 18)
    # -------------------------------------------------------------
    def test_privacy_redactor_and_dlp_boundary(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        sensitive_text = "Analysis conducted on /home/analyst_bob/malware/sample.exe by analyst_bob with key sk-1234567890abcdef1234567890abcdef"
        redacted = redactor.redact_string(sensitive_text)
        self.assertNotIn("analyst_bob", redacted)
        self.assertNotIn("sk-1234567890abcdef1234567890abcdef", redacted)
        self.assertIn("<REDACTED_USER>", redacted)
        self.assertTrue("[REDACTED_SECRET]" in redacted or "[REDACTED_API_KEY]" in redacted)

        # DLP transmission audit
        safe, reasons = redactor.audit_for_transmission({"key": "sk-real_unredacted_secret_key_12345"})
        self.assertFalse(safe)


    # -------------------------------------------------------------
    # 8. Evidence Deduplication & Graph (Phases 12, 13, 14)
    # -------------------------------------------------------------
    def test_evidence_deduplication_and_graph(self):
        store = EvidenceStore()
        rec1 = store.create("sample.exe", "PE_SECTION", "entropy", 7.8, "AnalyzerA")
        rec2 = store.create("sample.exe", "PE_SECTION", "entropy", 7.8, "AnalyzerB")

        # Duplicate should be linked, not duplicated
        self.assertEqual(rec1.evidence_id, rec2.evidence_id)
        self.assertEqual(rec1.duplicate_count, 2)
        self.assertEqual(len(store), 1)

        # Derived evidence with parent linkage
        derived = store.create(
            "sample.exe", "DERIVED", "packing_assessment", "High confidence packing",
            "HeuristicRule", parent_evidence_ids=[rec1.evidence_id],
            derivation_rule="EntropyThreshold_v1"
        )
        self.assertIn(rec1.evidence_id, derived.parent_evidence_ids)
        self.assertEqual(derived.derivation_rule, "EntropyThreshold_v1")

    # -------------------------------------------------------------
    # 9. SQLite Evidence Backend (Phase 12)
    # -------------------------------------------------------------
    def test_sqlite_evidence_backend(self):
        db_path = str(self.tmp_path / "test_evidence.db")
        store = EvidenceStore(backend="sqlite", db_path=db_path)
        
        r1 = store.create("artifact1", "TYPE_A", "field1", "val1", "ext1")
        r2 = store.create("artifact2", "TYPE_B", "field2", {"nested": 123}, "ext2")

        self.assertEqual(len(store), 2)
        found = store.find(source_artifact="artifact1")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].field, "field1")

        # Deduplication in SQLite
        r1_dup = store.create("artifact1", "TYPE_A", "field1", "val1", "ext1")
        self.assertEqual(r1.evidence_id, r1_dup.evidence_id)
        self.assertEqual(len(store), 2)

    # -------------------------------------------------------------
    # 10. PCAP Memory Limits & Calibrated Terminology (Phase 15 & 19)
    # -------------------------------------------------------------
    def test_pcap_memory_limits_and_constants(self):
        self.assertGreaterEqual(MAX_TRACKED_CONNECTIONS, 5000)
        self.assertGreaterEqual(MAX_TIMESTAMPS_PER_CONNECTION, 1000)

    # -------------------------------------------------------------
    # 11. AI Raw IOC & Behavioral Claims Rejection (Phase 3)
    # -------------------------------------------------------------
    def test_ai_raw_ioc_and_behavioral_claims_rejection(self):
        store = EvidenceStore()
        store.create("sample.exe", "PE_HEADER", "sha256", "abc123", "TestExtractor")
        engine = FindingEngine(store)
        findings = engine.analyze()
        baseline = engine.assess(findings)

        synthesizer = LLMThreatSynthesizer(provider="offline")
        fake_ai_output = {
            "hashes": ["fake_hash_123"],
            "domains": ["evil-c2.com"],
            "ips": ["1.2.3.4"],
            "c2_confirmation": True,
            "persistence_claims": "System autostart confirmed via scheduled task",
            "process_injection_confirmation": "Confirmed reflective DLL injection"
        }

        validated = synthesizer._merge_and_validate(fake_ai_output, baseline, store, findings=findings)
        ai_val = validated.ai_validation
        self.assertIsNotNone(ai_val)
        
        # Verify raw IOCs rejected
        self.assertIn("hashes", ai_val["rejected_fields"])
        self.assertIn("domains", ai_val["rejected_fields"])
        self.assertIn("ips", ai_val["rejected_fields"])

        # Verify behavioral claims rejected/downgraded
        self.assertIn("c2_confirmation", ai_val["rejected_fields"])
        self.assertIn("persistence_claims", ai_val["rejected_fields"])
        self.assertIn("process_injection_confirmation", ai_val["downgraded_fields"])

    # -------------------------------------------------------------
    # 12. Safe Process Execution Security (Phase 11)
    # -------------------------------------------------------------
    def test_safe_process_execution_guard(self):
        # Normal execution
        res = safe_run_process(["echo", "SAFE_TEST_OUTPUT"], timeout=5)
        self.assertEqual(res.exit_code, 0)
        self.assertIn("SAFE_TEST_OUTPUT", res.stdout)
        self.assertTrue(len(res.stdout_hash) == 64)

        # Non-list argument raises ValueError
        with self.assertRaises(ValueError):
            safe_run_process("echo not_allowed", timeout=5)  # type: ignore

        # Timeout enforcement
        timeout_res = safe_run_process(["sleep", "3"], timeout=1)
        self.assertTrue(timeout_res.timed_out)

    # -------------------------------------------------------------
    # 13. Evidence Appendix Generation & Traceability (Phase 20)
    # -------------------------------------------------------------
    def test_evidence_appendix_structure(self):
        from core.orchestrator import AnalysisOrchestrator
        out_dir = self.tmp_path / "case_appendix_test"
        orchestrator = AnalysisOrchestrator()
        result = orchestrator.analyze(
            sample_path=self.benign_file,
            output_dir=out_dir,
            offline=True,
            portable=True
        )

        # Check report.json contains evidence_appendix
        report_json_path = out_dir / "report.json"
        self.assertTrue(report_json_path.exists())
        data = json.loads(report_json_path.read_text(encoding="utf-8"))
        
        self.assertIn("evidence_appendix", data)
        appendix = data["evidence_appendix"]
        self.assertIsInstance(appendix, list)
        for item in appendix:
            self.assertIn("finding_id", item)
            self.assertIn("status", item)
            self.assertIn("confidence", item)
            self.assertIn("evidence_ids", item)
            self.assertIn("source_artifacts", item)
            self.assertIn("source_provenance", item)
            self.assertIn("derivation_rule", item)


if __name__ == "__main__":
    unittest.main()
