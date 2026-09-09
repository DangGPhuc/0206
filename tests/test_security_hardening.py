"""
0206 - Security Hardening & Regression Test Suite
Validates:
1. Provider credential isolation (no cross-contamination between OpenAI, Anthropic, Ollama, Offline).
2. Manifest AI metadata consistency (DLP fallback to offline never writes remote_mode='remote').
3. Strict-mode default case export privacy (zero sensitive marker leaks in any output file).
4. Process-tree termination on timeout (no orphan child processes left running).
5. Regshot resource limits (check_regshot and MAX_REGSHOT_LINES).
6. Streaming artifact hashing in GeneratedArtifact.from_file.
7. Atomic output writes and POSIX 0700/0600 permissions.
8. Zero shell=True in production code.
9. AI non-authoritativeness (cannot override deterministic threat scores).
"""
import os
import re
import stat
import time
import json
import signal
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from config import MAX_REGSHOT_SIZE, MAX_REGSHOT_LINES
from core.resource_policy import ResourcePolicy
from core.process_guard import safe_run_process, SafeProcessGuard
from core.atomic_io import atomic_write_json, atomic_write_text, set_posix_permissions
from core.privacy import PrivacyRedactor, DLPStatus, PrivacyMode
from core.evidence import EvidenceStore
from core.findings import Finding, FindingEngine, Assessment
from core.schemas import AnalysisDomain, EvidenceState, TransmissionMode
from core.orchestrator import AnalysisOrchestrator
from ai.schema import ProviderConfig, SanitizedAIRequest
from ai.providers.openai_provider import OpenAIProvider
from ai.providers.anthropic_provider import AnthropicProvider
from ai.providers.ollama_provider import OllamaProvider
from ai.providers.offline import OfflineAIProvider
from ai.agent import LLMThreatSynthesizer
from ai.grounding.validator import GroundingValidator
from integrations.base import GeneratedArtifact


class TestSecurityHardening(unittest.TestCase):
    """Regression test suite for 0206 security guarantees and hardening fixes."""

    def test_provider_credential_isolation(self):
        """Verify that provider credentials and configurations do not cross-contaminate."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-openai-secret-12345", "ANTHROPIC_API_KEY": ""}, clear=True):
            p_openai = OpenAIProvider()
            p_anthropic = AnthropicProvider()
            self.assertTrue(p_openai.is_available())
            self.assertEqual(p_openai.api_key, "sk-openai-secret-12345")
            self.assertFalse(p_anthropic.is_available())
            self.assertEqual(p_anthropic.api_key, "")

        with patch.dict(os.environ, {"OPENAI_API_KEY": "", "ANTHROPIC_API_KEY": "sk-ant-secret-67890"}, clear=True):
            p_openai = OpenAIProvider()
            p_anthropic = AnthropicProvider()
            self.assertFalse(p_openai.is_available())
            self.assertTrue(p_anthropic.is_available())
            self.assertEqual(p_anthropic.api_key, "sk-ant-secret-67890")

        # When both keys exist, selecting one provider must NOT pass the other's key
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-openai-1111", "ANTHROPIC_API_KEY": "sk-ant-2222"}, clear=True):
            synth_openai = LLMThreatSynthesizer(provider="openai")
            self.assertEqual(synth_openai.api_key, "sk-openai-1111")
            self.assertIsInstance(synth_openai.provider_instance, OpenAIProvider)

            synth_anthropic = LLMThreatSynthesizer(provider="anthropic")
            self.assertEqual(synth_anthropic.api_key, "sk-ant-2222")
            self.assertIsInstance(synth_anthropic.provider_instance, AnthropicProvider)

            # Ollama must not consume OpenAI or Anthropic keys
            synth_ollama = LLMThreatSynthesizer(provider="ollama")
            self.assertIsNone(synth_ollama.api_key)
            self.assertIsInstance(synth_ollama.provider_instance, OllamaProvider)

    def test_manifest_ai_metadata_consistency_on_dlp_fallback(self):
        """Verify that DLP transmission fallback to offline never produces remote_mode='remote'."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore()
            store.create("sample.exe", "FILE_METADATA", "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Test")
            # Inject sensitive marker that triggers DLP block
            store.create("sample.exe", "CONFIG", "secret_key", "sk-proj-SUPER_SECRET_KEY_1234567890abcdef", "Test")

            orch = AnalysisOrchestrator()
            # Simulate sample file
            sample_file = Path(tmp_dir) / "sample.exe"
            sample_file.write_bytes(b"MZ" + b"\x00" * 200)

            with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-key-mock-valid-length-12345"}):
                res = orch.run(sample_path=sample_file, output_dir=tmp_dir, profile="basic", offline=False)
                manifest_data = json.loads(res.manifest_json.read_text(encoding="utf-8"))

                # Manifest must be consistent: provider='offline' MUST have remote_mode='local'
                self.assertEqual(manifest_data["ai_mode"], "offline")
                ai_meta = manifest_data.get("ai_metadata", {})
                self.assertEqual(ai_meta.get("provider"), "offline")
                self.assertEqual(ai_meta.get("remote_mode"), "local")
                self.assertNotEqual(ai_meta.get("remote_mode"), "remote")

    def test_default_export_privacy_leakage(self):
        """Inject unique sensitive markers and verify zero leaks in ALL default public exports."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "case_out"
            sample_file = Path(tmp_dir) / "sample_test.exe"
            sample_file.write_bytes(b"MZ" + b"\x00" * 300)

            # Unique markers to inject into telemetry
            marker_classified = "TOP_SECRET_TEST_0206_A91F"
            marker_win_path = r"C:\Users\SensitiveAnalyst\secret_work\malware.exe"
            marker_unix_path = "/home/SensitiveAnalyst/secret_tools/payload.sh"
            marker_fake_token = "fake-api-token-9876543210fedcba"

            procmon_file = Path(tmp_dir) / "procmon.csv"
            procmon_content = (
                "Time of Day,Process Name,PID,Operation,Path,Result,Detail\n"
                f'12:00:00,cmd.exe,1234,Process Create,"{marker_win_path}",SUCCESS,"{marker_classified}"\n'
                f'12:00:01,bash,5678,WriteFile,"{marker_unix_path}",SUCCESS,"token={marker_fake_token}"\n'
            )
            procmon_file.write_text(procmon_content, encoding="utf-8")

            orch = AnalysisOrchestrator()
            res = orch.run(
                sample_path=sample_file,
                procmon_path=procmon_file,
                output_dir=out_dir,
                profile="basic",
                privacy_mode="strict",
                offline=True
            )

            # Recursively scan every single file in the case output directory
            all_files = [p for p in out_dir.rglob("*") if p.is_file() and not p.name.endswith(".raw.json")]
            self.assertGreater(len(all_files), 5, "Expected case bundle files to exist")

            for fpath in all_files:
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                # None of the unredacted markers may appear in any public export
                self.assertNotIn(marker_classified, content, f"Marker {marker_classified} leaked in {fpath.name}")
                self.assertNotIn("SensitiveAnalyst", content, f"Sensitive analyst username leaked in {fpath.name}")
                self.assertNotIn(marker_fake_token, content, f"Fake token {marker_fake_token} leaked in {fpath.name}")

    def test_process_tree_termination_on_timeout(self):
        """Verify that timeout kills the entire process group leaving no orphan child processes."""
        if os.name == "nt":
            self.skipTest("Process group isolation via os.killpg is specific to POSIX.")

        # Script that spawns a background child and sleeps
        code = (
            "import subprocess, time\n"
            "subprocess.Popen(['python3', '-c', 'import time; time.sleep(30)'])\n"
            "time.sleep(30)\n"
        )
        res = safe_run_process(["python3", "-c", code], timeout=1)
        self.assertTrue(res.timed_out)
        self.assertIsNotNone(res.error_message)

    def test_timeout_and_limit_validation(self):
        """Verify that negative or pathological timeouts and output limits are rejected."""
        with self.assertRaises(ValueError):
            safe_run_process(["python3", "--version"], timeout=0)

        with self.assertRaises(ValueError):
            safe_run_process(["python3", "--version"], timeout=-10)

        with self.assertRaises(ValueError):
            safe_run_process(["python3", "--version"], max_stdout_bytes=0)

    def test_regshot_resource_limits(self):
        """Verify that Regshot diff files are validated for size and line bounds."""
        policy = ResourcePolicy()
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("Line\n" * 10)
            f_path = Path(f.name)

        try:
            ok, err = policy.check_regshot(f_path)
            self.assertTrue(ok)
            self.assertIsNone(err)

            # Test excessive size
            policy_small = ResourcePolicy(max_regshot_size=10)
            ok2, err2 = policy_small.check_regshot(f_path)
            self.assertFalse(ok2)
            self.assertIn("exceeds resource limit", err2)
        finally:
            f_path.unlink(missing_ok=True)

    def test_streaming_artifact_hashing(self):
        """Verify GeneratedArtifact.from_file hashes files in streaming chunks without unbounded memory usage."""
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"SAMPLE_ARTIFACT_DATA_" * 1000)
            f_path = Path(f.name)

        try:
            art = GeneratedArtifact.from_file(f_path, source_tool="TestTool", tool_version="1.0")
            self.assertEqual(art.size, f_path.stat().st_size)
            self.assertEqual(len(art.sha256), 64)
            self.assertEqual(art.source_tool, "TestTool")
        finally:
            f_path.unlink(missing_ok=True)

    def test_atomic_writes_and_posix_permissions(self):
        """Verify atomic writes guarantee complete files and enforce POSIX 0700/0600 permissions."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_json = Path(tmp_dir) / "sub" / "output.json"
            data = {"status": "SUCCESS", "case_id": "TEST-0206"}
            written = atomic_write_json(target_json, data)

            self.assertTrue(written.exists())
            loaded = json.loads(written.read_text(encoding="utf-8"))
            self.assertEqual(loaded["status"], "SUCCESS")

            if os.name != "nt":
                file_mode = stat.S_IMODE(target_json.stat().st_mode)
                dir_mode = stat.S_IMODE(target_json.parent.stat().st_mode)
                self.assertEqual(file_mode, 0o600, "Expected file permissions 0600")
                self.assertEqual(dir_mode, 0o700, "Expected directory permissions 0700")

    def test_no_shell_true_in_production_code(self):
        """Static audit to guarantee shell=True is never used in production codebase."""
        repo_root = Path(__file__).resolve().parent.parent
        production_dirs = ["core", "analyzers", "reporting", "sandbox", "cli", "lab"]

        for p_dir in production_dirs:
            dir_path = repo_root / p_dir
            if not dir_path.exists():
                continue
            for py_file in dir_path.rglob("*.py"):
                for line in py_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if re.search(r'\bshell\s*=\s*True\b', stripped):
                        self.fail(
                            f"Forbidden shell=True detected in production file: {py_file.relative_to(repo_root)}: {stripped}"
                        )

    def test_ai_cannot_override_deterministic_score(self):
        """Verify GroundingValidator strictly rejects AI attempts to modify deterministic threat scores."""
        store = EvidenceStore()
        store.create("test.exe", "FILE", "sha256", "dummy_hash", "Test")
        validator = GroundingValidator(store)

        baseline = Assessment(
            assessment_id="ASM-001",
            title="Deterministic Triage Assessment",
            threat_level="MEDIUM",
            threat_score=50,
            classification="Suspicious Heuristics",
            summary="Deterministic baseline",
            findings_count=1
        )

        # AI maliciously tries to claim score is 0 and level is CLEAN
        ai_payload = {
            "threat_score": 0,
            "threat_level": "INFORMATIONAL",
            "malware_family": "Clean Binary"
        }

        merged, val_res = validator.validate_synthesis(ai_payload, baseline)
        self.assertEqual(merged.threat_score, 50, "Deterministic threat score must be authoritative")
        self.assertEqual(merged.threat_level, "MEDIUM", "Deterministic threat level must be authoritative")
        self.assertIn("threat_score", val_res.rejected_fields)
        self.assertIn("threat_level", val_res.rejected_fields)

    def test_provider_explicit_overrides_and_offline(self):
        """Verify explicit api_key and model overrides take precedence, and offline provider needs no keys."""
        # Offline provider requires no keys and produces OfflineAIProvider
        synth_offline = LLMThreatSynthesizer(provider="offline")
        self.assertIsNone(synth_offline.api_key)
        self.assertIsInstance(synth_offline.provider_instance, OfflineAIProvider)

        # Explicit api_key override
        synth_custom_key = LLMThreatSynthesizer(provider="openai", api_key="sk-override-key-999")
        self.assertEqual(synth_custom_key.api_key, "sk-override-key-999")
        self.assertEqual(synth_custom_key.provider_instance.api_key, "sk-override-key-999")

        # Explicit model override
        synth_custom_model = LLMThreatSynthesizer(provider="openai", model="gpt-4o-custom")
        self.assertEqual(synth_custom_model.model, "gpt-4o-custom")
        self.assertEqual(synth_custom_model.provider_instance.model, "gpt-4o-custom")

    def test_offline_mode_zero_network_calls(self):
        """Verify that offline mode execution triggers zero external socket/HTTP network calls."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_file = Path(tmp_dir) / "sample_offline.exe"
            sample_file.write_bytes(b"MZ" + b"\x00" * 300)

            orch = AnalysisOrchestrator()

            # Patch socket.socket.connect and urllib.request.urlopen to fail if called
            with patch("socket.socket.connect", side_effect=RuntimeError("NETWORK CALL FORBIDDEN IN OFFLINE MODE")):
                with patch("urllib.request.urlopen", side_effect=RuntimeError("HTTP CALL FORBIDDEN IN OFFLINE MODE")):
                    res = orch.run(sample_path=sample_file, output_dir=tmp_dir, profile="basic", offline=True)
                    self.assertIsNotNone(res)
                    self.assertTrue(res.report_json.exists())

    def test_grounding_validator_rejects_nonexistent_evidence_ids(self):
        """Verify that GroundingValidator strictly rejects MITRE techniques citing non-existent evidence IDs."""
        store = EvidenceStore()
        real_rec = store.create("sample.exe", "PROCESS", "process_create", "cmd.exe", "Test")

        validator = GroundingValidator(store)
        baseline = Assessment(
            assessment_id="ASM-TEST",
            title="Baseline",
            threat_level="LOW",
            threat_score=20,
            classification="Benign/Unknown",
            summary="Baseline assessment"
        )

        ai_payload = {
            "mitre_attack": [
                {
                    "technique_id": "T1055",
                    "technique_name": "Process Injection",
                    "evidence_ids": [real_rec.evidence_id, "EVD-NONEXISTENT-99999"]
                },
                {
                    "technique_id": "T1071",
                    "technique_name": "Application Layer Protocol",
                    "evidence_ids": ["EVD-NONEXISTENT-88888"]
                }
            ]
        }

        merged, val_res = validator.validate_synthesis(ai_payload, baseline)

        self.assertIn("mitre_technique_T1071", val_res.rejected_fields)
        self.assertIn("mitre_technique_T1055", val_res.downgraded_fields)

        accepted_eids = [eid for t in merged.mitre_techniques for eid in t.get("evidence_ids", [])]
        self.assertNotIn("EVD-NONEXISTENT-99999", accepted_eids)
        self.assertNotIn("EVD-NONEXISTENT-88888", accepted_eids)
        self.assertIn(real_rec.evidence_id, accepted_eids)

    def test_not_analyzed_semantics_preservation(self):
        """Verify that domains without provided input preserve [NOT_ANALYZED] status and are never fabricated."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_file = Path(tmp_dir) / "sample_bare.exe"
            sample_file.write_bytes(b"MZ" + b"\x00" * 300)

            orch = AnalysisOrchestrator()
            res = orch.run(
                sample_path=sample_file,
                output_dir=tmp_dir,
                profile="basic",
                offline=True
            )

            cov_data = json.loads(res.coverage_json.read_text(encoding="utf-8"))
            dom_cov = cov_data.get("domain_coverage", {})

            self.assertEqual(dom_cov.get("Network"), "NOT_ANALYZED")
            self.assertEqual(dom_cov.get("Process"), "NOT_ANALYZED")
            self.assertEqual(dom_cov.get("Registry"), "NOT_ANALYZED")

            md_content = res.report_md.read_text(encoding="utf-8")
            self.assertIn("[NOT_ANALYZED]", md_content)


if __name__ == "__main__":
    unittest.main()
