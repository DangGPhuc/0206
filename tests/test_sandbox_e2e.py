"""
End-to-End Orchestrator Sandbox Detonation Integration Tests.
Verifies harmless mocked detonation pipeline:
  Sample fixture -> Mock Sandbox -> Telemetry Collection -> BehavioralAnalyzer ->
  EvidenceStore -> Findings -> Offline AI -> Report & Case Deliverables.
Ensures zero execution calls when detonate=False.
"""
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import json
import hashlib

from core.orchestrator import AnalysisOrchestrator
from sandbox.schema import (
    SandboxGuestConfig,
    SandboxExecutionTrace,
    SandboxStatus,
    SandboxNetworkState,
    ActionStatus,
    SandboxActionRecord,
)


class TestSandboxE2E(unittest.TestCase):

    def setUp(self):
        self.orchestrator = AnalysisOrchestrator()
        self.fixture_exe = Path(__file__).parent / "sample_benign_triage.exe"

    def test_detonate_false_makes_zero_sandbox_calls(self):
        """When detonate=False (default), sandbox must not be invoked at all."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch("core.orchestrator.SandboxController") as mock_ctrl:
                res = self.orchestrator.run(
                    sample_path=self.fixture_exe,
                    output_dir=tmp_dir,
                    profile="minimal",
                    offline=True,
                    detonate=False
                )
                mock_ctrl.assert_not_called()
                self.assertIsNone(res.manifest.sandbox_trace_hash)
                # Ensure no sandbox/ directory in output
                self.assertFalse((Path(tmp_dir) / "sandbox").exists())

    def test_mocked_sandbox_e2e_pipeline(self):
        """
        Harmless mocked E2E workflow:
        detonate=True -> fake sandbox telemetry -> BehavioralAnalyzer ->
        EvidenceStore -> Findings -> Offline AI -> Case bundle & Report.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            sandbox_mock_dir = Path(tmp_dir) / "mock_sandbox_telemetry"
            sandbox_mock_dir.mkdir(parents=True, exist_ok=True)

            # 1. Create fake safe telemetry artifacts
            procmon_file = sandbox_mock_dir / "procmon.csv"
            procmon_file.write_text(
                '"Time of Day","Process Name","PID","Operation","Path","Result","Detail"\n'
                '"10:00:00.000","sample.exe",1234,"Process Create","C:\\Windows\\System32\\cmd.exe","SUCCESS","PID: 5678"\n'
                '"10:00:01.000","sample.exe",1234,"RegSetValue","HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TestApp","SUCCESS","Type: REG_SZ, Length: 24, Data: C:\\0206\\work\\sample.exe"\n'
            )

            pcap_file = sandbox_mock_dir / "network.pcap"
            pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 32)

            regshot_file = sandbox_mock_dir / "regshot.txt"
            regshot_file.write_text("----------------------------------\nKeys added: 1\nValues added: 1\n----------------------------------\n")

            meta_file = sandbox_mock_dir / "execution_metadata.json"
            meta_file.write_text(json.dumps({
                "processes": [{"name": "sample.exe", "pid": 1234}, {"name": "cmd.exe", "pid": 5678}],
                "dropped_files": [
                    {
                        "filename": "dropped_helper.dll",
                        "guest_path": r"C:\0206\work\dropped_helper.dll",
                        "size": 2048,
                        "sha256": "3a7b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b"
                    }
                ]
            }))

            # 2. Build mock trace
            mock_trace = SandboxExecutionTrace(
                trace_id="vbox-e2e-test",
                backend_name="virtualbox",
                vm_name="win10-malware-analysis",
                snapshot_name="clean_triage_base",
                network_mode="HOST_ONLY",
                network_verification_status="VERIFIED_HOST_ONLY",
                status=SandboxStatus.COMPLETED,
                execution_duration=12.5,
                sample_guest_path=r"C:\0206\work\sample.exe",
                sample_sha256="fake_sha256_for_sample",
                pcap_path=str(pcap_file),
                procmon_csv_path=str(procmon_file),
                regshot_path=str(regshot_file),
                execution_metadata_path=str(meta_file),
                processes_spawned=[{"name": "sample.exe", "pid": 1234}],
                dropped_file_metadata=[
                    {
                        "filename": "dropped_helper.dll",
                        "guest_path": r"C:\0206\work\dropped_helper.dll",
                        "size": 2048,
                        "sha256": "3a7b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b"
                    }
                ],
                telemetry_hashes={
                    "procmon.csv": hashlib.sha256(procmon_file.read_bytes()).hexdigest(),
                    "network.pcap": hashlib.sha256(pcap_file.read_bytes()).hexdigest(),
                },
                execution_status="EXECUTED",
                revert_status="VERIFIED",
                cleanup_status="SUCCESS"
            )

            # 3. Patch SandboxController so it returns our fake trace
            with patch("core.orchestrator.SandboxController") as mock_ctrl_cls:
                mock_ctrl_inst = MagicMock()
                mock_ctrl_inst.detonate.return_value = mock_trace
                mock_ctrl_inst.run_safe_session.return_value = mock_trace
                mock_ctrl_cls.return_value = mock_ctrl_inst

                res = self.orchestrator.run(
                    sample_path=self.fixture_exe,
                    output_dir=tmp_dir,
                    profile="minimal",
                    offline=True,
                    detonate=True,
                    sandbox_backend="virtualbox"
                )

                # 4. Verify SandboxController was invoked
                mock_ctrl_cls.assert_called_once()
                self.assertTrue(mock_ctrl_inst.run_safe_session.called or mock_ctrl_inst.detonate.called)

                # 5. Verify case/sandbox/ directory and artifacts exist
                sandbox_dir = Path(tmp_dir) / "sandbox"
                self.assertTrue(sandbox_dir.exists())
                self.assertTrue((sandbox_dir / "sandbox_trace.json").exists())
                self.assertTrue((sandbox_dir / "procmon.csv").exists())
                self.assertTrue((sandbox_dir / "network.pcap").exists())
                self.assertTrue((sandbox_dir / "regshot.txt").exists())
                self.assertTrue((sandbox_dir / "execution_metadata.json").exists())

                # 6. Verify manifest records sandbox trace hash and lineage
                self.assertIsNotNone(res.manifest.sandbox_trace_hash)
                self.assertIn("sandbox/sandbox_trace.json", res.manifest.output_lineage)
                self.assertIn("sandbox/procmon.csv", res.manifest.output_lineage)

                # 7. Verify sandbox provenance EvidenceRecords in evidence store
                provenance_records = [
                    rec for rec in res.evidence_store.all()
                    if rec.source_type == "SANDBOX_PROVENANCE"
                ]
                self.assertGreater(len(provenance_records), 0)
                # Ensure provenance is classified non-maliciously
                for pr in provenance_records:
                    self.assertIn(pr.field, ("backend", "vm_name", "snapshot_name", "snapshot_uuid", "sandbox_network_mode", "verified_network_mode", "trace_id", "execution_duration", "telemetry_artifact_hashes"))

                # 8. Verify report contains Sandbox Execution section
                report_text = res.report_md.read_text(encoding="utf-8")
                self.assertIn("Sandbox Backend:** `virtualbox`", report_text)
                self.assertIn("VERIFIED_HOST_ONLY", report_text)
                self.assertIn("clean_triage_base", report_text)

                # 9. Verify embedded manifest in report matches final manifest (Requirement 12)
                report_data = json.loads(res.report_json.read_text(encoding="utf-8"))
                embedded_manifest = report_data.get("manifest", {})
                self.assertEqual(embedded_manifest.get("sandbox_trace_hash"), res.manifest.sandbox_trace_hash)
                self.assertEqual(embedded_manifest.get("sandbox_provider"), res.manifest.sandbox_provider)
                self.assertEqual(embedded_manifest.get("sandbox_network_mode"), res.manifest.sandbox_network_mode)
                self.assertEqual(embedded_manifest.get("sandbox_network_verification_status"), res.manifest.sandbox_network_verification_status)
                self.assertIn("sandbox/sandbox_trace.json", embedded_manifest.get("output_lineage", {}))
                self.assertIn("sandbox/procmon.csv", embedded_manifest.get("output_lineage", {}))
                self.assertEqual(
                    embedded_manifest["output_lineage"]["sandbox/sandbox_trace.json"],
                    res.manifest.output_lineage["sandbox/sandbox_trace.json"]
                )

    def test_orchestrator_gates_telemetry_on_failed_sandbox_status(self):
        """
        Requirement 11: A failed/partial/unverified sandbox session must NOT ingest
        telemetry as confirmed runtime behavioral evidence.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            sandbox_mock_dir = Path(tmp_dir) / "mock_sandbox_telemetry"
            sandbox_mock_dir.mkdir(parents=True, exist_ok=True)
            procmon_file = sandbox_mock_dir / "procmon.csv"
            procmon_file.write_text('"Time","Process Name","PID","Operation"\n"10:00:00","sample.exe",1234,"Process Create"\n')

            failed_trace = SandboxExecutionTrace(
                trace_id="vbox-failed-trace",
                backend_name="virtualbox",
                vm_name="win10-malware-analysis",
                snapshot_name="clean_triage_base",
                network_mode="HOST_ONLY",
                network_verification_status="UNVERIFIED",
                status=SandboxStatus.FAILED,
                procmon_csv_path=str(procmon_file),
                telemetry_hashes={"procmon.csv": hashlib.sha256(procmon_file.read_bytes()).hexdigest()},
                execution_status="FAILED",
            )

            with patch("core.orchestrator.SandboxController") as mock_ctrl_cls:
                mock_ctrl_inst = MagicMock()
                mock_ctrl_inst.detonate.return_value = failed_trace
                mock_ctrl_inst.run_safe_session.return_value = failed_trace
                mock_ctrl_cls.return_value = mock_ctrl_inst

                res = self.orchestrator.run(
                    sample_path=self.fixture_exe,
                    output_dir=tmp_dir,
                    profile="minimal",
                    offline=True,
                    detonate=True,
                    sandbox_backend="virtualbox"
                )

                # Verify that behavioral events were NOT ingested into evidence store
                behavioral_records = [
                    rec for rec in res.evidence_store.all()
                    if rec.source_type in ("PROCMON_EVENT", "BEHAVIORAL_PROCESS")
                ]
                self.assertEqual(len(behavioral_records), 0)


if __name__ == "__main__":
    unittest.main()
