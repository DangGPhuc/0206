"""
Unit tests for VirtualBox reference sandbox backend and sandbox doctor.
Uses mocked SafeProcessGuard to verify VBoxManage command invocations,
default-deny network inspection, credential redaction, and telemetry collection.
"""
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import os
import io
from rich.console import Console

from core.process_guard import ProcessExecutionResult
from sandbox.schema import (
    SandboxGuestConfig,
    SandboxNetworkMode,
    SandboxNetworkState,
    ActionStatus,
)
from sandbox.backends.virtualbox import VirtualBoxSandboxBackend
from sandbox.doctor import run_sandbox_doctor


def make_exec_result(cmd, exit_code=0, stdout="", stderr="", timed_out=False):
    return ProcessExecutionResult(
        command=cmd,
        exit_code=exit_code,
        duration_ms=10.0,
        stdout=stdout,
        stderr=stderr,
        stdout_hash="dummy_hash",
        stderr_hash="dummy_hash",
        timed_out=timed_out,
    )


class TestVirtualBoxBackend(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.config = SandboxGuestConfig(
            backend="virtualbox",
            vm_name="test_analysis_vm",
            snapshot_name="test_clean_base",
            guest_username="analyst",
            guest_password_env="TEST_SANDBOX_PWD",
            guest_work_dir=r"C:\0206\work",
            guest_telemetry_dir=r"C:\0206\telemetry",
            network_mode=SandboxNetworkMode.HOST_ONLY,
        )
        os.environ["TEST_SANDBOX_PWD"] = "super_secret_guest_pass"
        self.backend = VirtualBoxSandboxBackend(self.config, vbox_bin="/usr/bin/VBoxManage")
        self.backend.is_available = MagicMock(return_value=True)

    def tearDown(self):
        self.tmp_dir.cleanup()
        if "TEST_SANDBOX_PWD" in os.environ:
            del os.environ["TEST_SANDBOX_PWD"]

    @patch("shutil.which")
    def test_is_available_detection(self, mock_which):
        backend_ok = VirtualBoxSandboxBackend(self.config, vbox_bin="/usr/bin/VBoxManage")
        mock_which.return_value = "/usr/bin/VBoxManage"
        self.assertTrue(backend_ok.is_available())

        backend_none = VirtualBoxSandboxBackend(self.config, vbox_bin=None)
        mock_which.return_value = None
        self.assertFalse(backend_none.is_available())

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_verify_vm_success_and_failure(self, mock_run):
        # Success when showvminfo succeeds
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='name="test_analysis_vm"\nVMState="poweroff"\n'
        )
        rec = self.backend.verify_vm()
        self.assertTrue(rec.is_success())
        self.assertEqual(rec.status, ActionStatus.VERIFIED.value)

        # Failure when showvminfo returns non-zero
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=1,
            stderr="VBOX_E_OBJECT_NOT_FOUND"
        )
        rec_fail = self.backend.verify_vm()
        self.assertFalse(rec_fail.is_success())
        self.assertEqual(rec_fail.status, ActionStatus.FAILED.value)

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_verify_baseline_snapshot(self, mock_run):
        # Found snapshot
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "snapshot", "test_analysis_vm", "list", "--machinereadable"],
            exit_code=0,
            stdout='SnapshotName="test_clean_base"\nSnapshotUUID="abcd-1234"\n'
        )
        rec = self.backend.verify_baseline()
        self.assertTrue(rec.is_success())

        # Missing snapshot
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "snapshot", "test_analysis_vm", "list", "--machinereadable"],
            exit_code=0,
            stdout='SnapshotName="other_snapshot"\n'
        )
        rec_fail = self.backend.verify_baseline()
        self.assertFalse(rec_fail.is_success())

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_verify_network_leak_detection(self, mock_run):
        # NAT configured on NIC1 -> must flag LEAK_DETECTED and fail
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='nic1="nat"\nmacaddress1="080027123456"\n'
        )
        rec = self.backend.verify_network()
        self.assertFalse(rec.is_success())
        self.assertEqual(self.backend.network_state, SandboxNetworkState.LEAK_DETECTED)
        self.assertIn("Hostile detonation default-denies", rec.details)

        # Bridged configured -> must flag LEAK_DETECTED and fail
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='nic1="bridged"\nbridgeadapter1="eth0"\n'
        )
        rec = self.backend.verify_network()
        self.assertFalse(rec.is_success())
        self.assertEqual(self.backend.network_state, SandboxNetworkState.LEAK_DETECTED)

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_verify_network_safe_host_only(self, mock_run):
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='nic1="hostonly"\nhostonlyadapter1="vboxnet0"\nnic2="none"\n'
        )
        rec = self.backend.verify_network()
        self.assertTrue(rec.is_success())
        self.assertEqual(self.backend.network_state, SandboxNetworkState.VERIFIED_HOST_ONLY)

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_credential_redaction_in_commands(self, mock_run):
        """Plaintext guest passwords must never appear in command logs or records."""
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "guestcontrol", "test_analysis_vm", "run", "--password", "super_secret_guest_pass"],
            exit_code=0,
            stdout="0206_READY\n"
        )
        rec = self.backend.verify_guest_control()
        self.assertTrue(rec.is_success())
        for action in self.backend.actions:
            self.assertNotIn("super_secret_guest_pass", action.details)
            for err in action.errors:
                self.assertNotIn("super_secret_guest_pass", err)

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_restore_baseline_command(self, mock_run):
        res_info = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='VMState="poweroff"\n'
        )
        res_restore = make_exec_result(
            ["/usr/bin/VBoxManage", "snapshot", "test_analysis_vm", "restore", "test_clean_base"],
            exit_code=0,
            stdout="Restoring snapshot 100%\n"
        )
        mock_run.side_effect = [res_info, res_restore]

        rec = self.backend.restore_baseline()
        self.assertTrue(rec.is_success())
        args = mock_run.call_args[0][0]
        self.assertEqual(args, ["/usr/bin/VBoxManage", "snapshot", "test_analysis_vm", "restore", "test_clean_base"])

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_collect_telemetry_and_dropped_file_metadata(self, mock_run):
        """Verifies collecting telemetry files and dropped file metadata without copying dropped binaries."""
        with tempfile.TemporaryDirectory() as out_dir:
            mock_run.return_value = make_exec_result(
                ["/usr/bin/VBoxManage", "guestcontrol", "test_analysis_vm", "copyfrom"],
                exit_code=0,
                stdout="Copied files\n"
            )

            # Pre-populate the collected telemetry files in out_dir
            out_p = Path(out_dir)
            (out_p / "procmon.csv").write_text('"Process Name","PID","Operation"\n"sample.exe",1234,"Process Create"\n')
            (out_p / "network.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            (out_p / "regshot.txt").write_text("Keys added: 2\n")
            (out_p / "execution_metadata.json").write_text('{"processes": [{"name": "sample.exe", "pid": 1234}], "dropped_files": [{"filename": "dropped.dll", "path": "C:\\\\work\\\\dropped.dll", "size": 1024, "sha256": "abcdef123456"}]}')

            trace = self.backend.collect(out_dir)
            self.assertIsNotNone(trace.procmon_csv_path)
            self.assertIsNotNone(trace.pcap_path)
            self.assertIsNotNone(trace.regshot_path)
            self.assertEqual(len(trace.dropped_file_metadata), 1)
            self.assertEqual(trace.dropped_file_metadata[0]["sha256"], "abcdef123456")
            self.assertIn("procmon.csv", trace.telemetry_hashes)
            self.assertIn("network.pcap", trace.telemetry_hashes)

    @patch("shutil.which")
    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_sandbox_doctor_healthy(self, mock_run, mock_which):
        mock_which.return_value = "/usr/bin/VBoxManage"
        # 1. showvminfo for VM check
        res_info1 = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='name="test_analysis_vm"\n'
        )
        # 2. list snapshots
        res_snaps = make_exec_result(
            ["/usr/bin/VBoxManage", "snapshot", "test_analysis_vm", "list", "--machinereadable"],
            exit_code=0,
            stdout='SnapshotName="test_clean_base"\n'
        )
        # 3. showvminfo for network verification
        res_info2 = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='nic1="hostonly"\nhostonlyadapter1="vboxnet0"\n'
        )
        # 4. guestcontrol preflight
        res_ctrl = make_exec_result(
            ["/usr/bin/VBoxManage", "guestcontrol", "test_analysis_vm", "run"],
            exit_code=0,
            stdout="0206_READY\n"
        )
        mock_run.side_effect = [res_info1, res_snaps, res_info2, res_ctrl]

        console = Console(file=io.StringIO())
        healthy = run_sandbox_doctor(console, "virtualbox", self.config)
        self.assertTrue(healthy)


if __name__ == "__main__":
    unittest.main()
