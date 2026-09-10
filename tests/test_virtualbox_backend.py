"""
Unit tests for VirtualBox reference sandbox backend and sandbox doctor.
Uses mocked SafeProcessGuard and fake VBoxManage script fixture to verify:
- VirtualBox config environment (VBOX_USER_HOME) propagation
- Zero plaintext passwords in argv, ActionRecord, or logs
- Fake VBoxManage executable fixture validating copyfrom argv (no pre-created files)
- Rejection of malformed copyfrom
- Strong snapshot revert verification (blank snapshot rejected, UUID mismatch rejected)
- Fail-closed telemetry startup (Procmon/tshark missing blocks execution)
- Truthful execute status semantics (START_FAILED, STARTED, EXITED, TIMED_OUT)
- Default-deny network verification (NAT/Bridged leak detection, simulated internet verification)
- Two-stage sandbox doctor (HOST_PREFLIGHT + GUEST_PREFLIGHT)
"""
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import stat
import json
import os
import io
import sys
from rich.console import Console

from core.process_guard import ProcessExecutionResult, SafeProcessGuard
from sandbox.schema import (
    SandboxGuestConfig,
    SandboxNetworkMode,
    SandboxNetworkState,
    ActionStatus,
    ExecutionSubStatus,
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
            vbox_user_home=os.path.join(self.tmp_dir.name, "vbox_config"),
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

    # =========================================================================
    # Requirement 1: VirtualBox Host Environment & VBOX_USER_HOME
    # =========================================================================
    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_vbox_user_home_environment_propagation(self, mock_run):
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='name="test_analysis_vm"\nVMState="poweroff"\n'
        )
        self.backend._run_vbox(["showvminfo", "test_analysis_vm"])
        self.assertTrue(mock_run.called)
        call_kwargs = mock_run.call_args[1]
        self.assertIn("extra_env", call_kwargs)
        self.assertEqual(call_kwargs["extra_env"].get("VBOX_USER_HOME"), self.config.vbox_user_home)

    # =========================================================================
    # Requirement 14: Credential Handling & Passwordfile
    # =========================================================================
    def test_guest_auth_args_uses_mode_0600_passwordfile_and_no_plaintext_password(self):
        """Plaintext guest passwords must never appear in argv and passwordfile must be mode 0600."""
        with self.backend._guest_auth_args() as auth_args:
            self.assertIn("--username", auth_args)
            self.assertIn("analyst", auth_args)
            self.assertIn("--passwordfile", auth_args)
            self.assertNotIn("--password", auth_args)
            self.assertNotIn("super_secret_guest_pass", auth_args)

            # Find the path of the password file
            pwd_idx = auth_args.index("--passwordfile") + 1
            pwd_path = auth_args[pwd_idx]
            self.assertTrue(os.path.exists(pwd_path))
            # Verify restrictive mode 0600
            file_mode = stat.S_IMODE(os.stat(pwd_path).st_mode)
            self.assertEqual(file_mode, 0o600)
            with open(pwd_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertEqual(content, "super_secret_guest_pass")

        # After context exit, the password file must be deleted
        self.assertFalse(os.path.exists(pwd_path))

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_credential_redaction_in_actions_and_logs(self, mock_run):
        """Plaintext guest passwords must never appear in command logs, action records, or details."""
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "guestcontrol", "test_analysis_vm", "run", "--passwordfile", "/tmp/dummy"],
            exit_code=0,
            stdout="0206_READY\n"
        )
        rec = self.backend.verify_guest_control()
        self.assertTrue(rec.is_success())
        for action in self.backend.actions:
            self.assertNotIn("super_secret_guest_pass", action.details)
            for err in action.errors:
                self.assertNotIn("super_secret_guest_pass", err)

    # =========================================================================
    # Requirement 4: Guest-to-Host Copy & Fake VBoxManage Executable Fixture
    # =========================================================================
    def _create_fake_vboxmanage(self, script_dir: Path) -> Path:
        """
        Creates a fake VBoxManage executable fixture that validates argv.
        Ensures copyfrom adheres to VirtualBox 7.1 syntax:
        guestcontrol <vm> --username <user> --passwordfile <file> copyfrom <guest_src> <host_dst>
        Creates destination file ONLY if argv is valid.
        Exits with 1 if argv is malformed.
        """
        fake_vbox = script_dir / "fake_vboxmanage.py"
        fake_vbox.write_text("""#!/usr/bin/env python3
import sys
import os
import json
from pathlib import Path

args = sys.argv[1:]

if "guestcontrol" in args:
    # Reject plaintext --password
    if "--password" in args:
        sys.stderr.write("ERROR: Plaintext --password forbidden!\\n")
        sys.exit(2)
    # Require --passwordfile
    if "--passwordfile" not in args:
        sys.stderr.write("ERROR: Missing --passwordfile!\\n")
        sys.exit(2)

    if "copyfrom" in args:
        # Validate copyfrom arguments: guestcontrol <vm> ... copyfrom <guest_src> <host_dst>
        idx = args.index("copyfrom")
        copy_args = [a for a in args[idx+1:] if not a.startswith("--")]
        if len(copy_args) < 2:
            sys.stderr.write(f"ERROR: Malformed copyfrom argv: {args}\\n")
            sys.exit(1)

        guest_src, host_dst = copy_args[0], copy_args[1]
        host_path = Path(host_dst)
        host_path.parent.mkdir(parents=True, exist_ok=True)

        if host_path.name == "procmon.csv":
            host_path.write_text('"Time","Process Name","PID","Operation"\\n"10:00:00","sample.exe",1234,"Process Create"\\n')
        elif host_path.name == "network.pcap":
            host_path.write_bytes(b"\\xd4\\xc3\\xb2\\xa1" + b"\\x00" * 32)
        elif host_path.name == "regshot.txt":
            host_path.write_text("----------------------------------\\nKeys added: 1\\n")
        elif host_path.name == "execution_metadata.json":
            host_path.write_text(json.dumps({
                "trace_id": "test_trace",
                "sample_sha256": "fake_hash",
                "processes": [{"name": "sample.exe", "pid": 1234}],
                "dropped_files": [{"filename": "dropped.dll", "guest_path": "C:\\\\0206\\\\work\\\\dropped.dll", "size": 1024, "sha256": "abc123"}]
            }))
        else:
            host_path.write_text("data")
        sys.exit(0)

    if "copyto" in args:
        sys.exit(0)

    if "run" in args:
        args_str = " ".join(args)
        if "preflight.ps1" in args_str:
            print(json.dumps({
                "tools": {
                    "procmon": {"installed": True, "path": "C:\\\\0206\\\\tools\\\\procmon.exe", "version": "3.92"},
                    "tshark": {"installed": True, "path": "C:\\\\0206\\\\tools\\\\tshark.exe", "version": "4.0.0"},
                    "regshot": {"installed": True, "path": "C:\\\\0206\\\\tools\\\\regshot.exe", "automated": True}
                },
                "network": {
                    "routes_verified": True,
                    "egress_blocked": True,
                    "simulated_services": True
                }
            }))
            sys.exit(0)
        else:
            print("0206_READY")
            sys.exit(0)

if "showvminfo" in args:
    print('name="test_analysis_vm"')
    print('VMState="poweroff"')
    print('nic1="hostonly"')
    print('hostonlyadapter1="vboxnet0"')
    print('CurrentSnapshotName="test_clean_base"')
    print('CurrentSnapshotUUID="uuid-1234-base"')
    sys.exit(0)

if "snapshot" in args:
    if "list" in args:
        print('SnapshotName="test_clean_base"')
        print('SnapshotUUID="uuid-1234-base"')
        sys.exit(0)
    elif "restore" in args:
        print("Restoring snapshot 100%")
        sys.exit(0)

if "startvm" in args:
    print("VM has been successfully started.")
    sys.exit(0)

if "controlvm" in args:
    print("0%...100%")
    sys.exit(0)

sys.exit(0)
""")
        fake_vbox.chmod(fake_vbox.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return fake_vbox

    def test_collect_with_fake_vboxmanage_creates_files_from_valid_argv(self):
        """
        Requirement 4 & 15: Tests must NOT pre-create destination files.
        The fake VBoxManage executable validates copyfrom argv and creates the files only upon valid syntax.
        """
        fake_vbox = self._create_fake_vboxmanage(Path(self.tmp_dir.name))
        backend = VirtualBoxSandboxBackend(self.config, vbox_bin=str(fake_vbox))
        backend.is_available = MagicMock(return_value=True)

        collect_dir = Path(self.tmp_dir.name) / "collected_telemetry"
        # Ensure collection directory contains ZERO pre-created files
        self.assertFalse(collect_dir.exists())

        trace = backend.collect(str(collect_dir))

        self.assertIsNotNone(trace.procmon_csv_path)
        self.assertIsNotNone(trace.pcap_path)
        self.assertIsNotNone(trace.regshot_path)
        self.assertIsNotNone(trace.execution_metadata_path)
        self.assertEqual(len(trace.dropped_file_metadata), 1)
        self.assertEqual(trace.dropped_file_metadata[0]["filename"], "dropped.dll")
        self.assertIn("procmon.csv", trace.telemetry_hashes)
        self.assertIn("network.pcap", trace.telemetry_hashes)
        self.assertIn("regshot.txt", trace.telemetry_hashes)

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_malformed_copyfrom_fails_closed(self, mock_run):
        """Malformed copyfrom (e.g. exit code 1 from VBoxManage) must not magically succeed."""
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "guestcontrol", "test_analysis_vm", "copyfrom"],
            exit_code=1,
            stderr="VBoxManage: error: Missing target parameter"
        )
        collect_dir = Path(self.tmp_dir.name) / "malformed_test"
        trace = self.backend.collect(str(collect_dir))
        # Files were not created, so paths and hashes must be empty/None
        self.assertIsNone(trace.procmon_csv_path)
        self.assertIsNone(trace.pcap_path)
        self.assertEqual(len(trace.telemetry_hashes), 0)

    # =========================================================================
    # Requirement 5: Strong Snapshot Revert Verification
    # =========================================================================
    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_verify_clean_rejection_of_blank_snapshot_name(self, mock_run):
        """CurrentSnapshotName being blank MUST fail clean verification."""
        self.backend._baseline_snapshot_uuid = "uuid-1234-base"
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='VMState="poweroff"\nCurrentSnapshotName=""\nCurrentSnapshotUUID=""\n'
        )
        rec = self.backend.verify_clean()
        self.assertFalse(rec.is_success())
        self.assertEqual(rec.status, ActionStatus.FAILED.value)
        self.assertIn("blank", rec.details.lower())

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_verify_clean_rejection_of_snapshot_uuid_mismatch(self, mock_run):
        """CurrentSnapshotUUID mismatch against baseline MUST fail clean verification."""
        self.backend._baseline_snapshot_uuid = "uuid-1234-base"
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='VMState="poweroff"\nCurrentSnapshotName="test_clean_base"\nCurrentSnapshotUUID="uuid-different-5678"\n'
        )
        rec = self.backend.verify_clean()
        self.assertFalse(rec.is_success())
        self.assertEqual(rec.status, ActionStatus.FAILED.value)
        self.assertIn("UUID mismatch", rec.details)

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_verify_clean_rejection_of_running_state(self, mock_run):
        """VMState not 'poweroff' MUST fail clean verification."""
        self.backend._baseline_snapshot_uuid = "uuid-1234-base"
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='VMState="running"\nCurrentSnapshotName="test_clean_base"\nCurrentSnapshotUUID="uuid-1234-base"\n'
        )
        rec = self.backend.verify_clean()
        self.assertFalse(rec.is_success())
        self.assertEqual(rec.status, ActionStatus.FAILED.value)

    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_verify_clean_success(self, mock_run):
        """Clean verification succeeds when VMState is poweroff and snapshot name and UUID match baseline."""
        self.backend._baseline_snapshot_uuid = "uuid-1234-base"
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=0,
            stdout='VMState="poweroff"\nCurrentSnapshotName="test_clean_base"\nCurrentSnapshotUUID="uuid-1234-base"\n'
        )
        rec = self.backend.verify_clean()
        self.assertTrue(rec.is_success())
        self.assertEqual(rec.status, ActionStatus.VERIFIED.value)

    # =========================================================================
    # Requirement 2: Start Telemetry Fail-Closed
    # =========================================================================
    @patch("sandbox.backends.virtualbox.VirtualBoxSandboxBackend._run_guest_ps_script")
    def test_start_telemetry_fails_closed_when_procmon_missing(self, mock_script):
        """If required Procmon fails to launch, start_telemetry must return FAILED."""
        self.config.require_procmon = True
        mock_script.return_value = make_exec_result(
            ["guestcontrol", "run", "start_telemetry.ps1"],
            exit_code=1,
            stdout=json.dumps({
                "procmon": {"started": False, "error": "Procmon executable not found"},
                "tshark": {"started": True, "pid": 5678},
                "regshot": {"started": True}
            })
        )
        rec = self.backend.start_telemetry()
        self.assertFalse(rec.is_success())
        self.assertEqual(rec.status, ActionStatus.FAILED.value)
        self.assertIn("Procmon", rec.details)

    @patch("sandbox.backends.virtualbox.VirtualBoxSandboxBackend._run_guest_ps_script")
    def test_start_telemetry_fails_closed_when_tshark_missing(self, mock_script):
        """If required tshark fails to launch, start_telemetry must return FAILED."""
        self.config.require_pcap = True
        mock_script.return_value = make_exec_result(
            ["guestcontrol", "run", "start_telemetry.ps1"],
            exit_code=1,
            stdout=json.dumps({
                "procmon": {"started": True, "pid": 1234},
                "tshark": {"started": False, "error": "tshark executable not found"},
                "regshot": {"started": True}
            })
        )
        rec = self.backend.start_telemetry()
        self.assertFalse(rec.is_success())
        self.assertEqual(rec.status, ActionStatus.FAILED.value)
        self.assertIn("tshark", rec.details)

    @patch("sandbox.backends.virtualbox.VirtualBoxSandboxBackend._run_guest_ps_script")
    def test_start_telemetry_partial_when_optional_regshot_missing(self, mock_script):
        """When optional Regshot fails, start_telemetry returns PARTIAL, not FAILED."""
        self.config.require_procmon = True
        self.config.require_pcap = True
        self.config.require_regshot = False
        mock_script.return_value = make_exec_result(
            ["guestcontrol", "run", "start_telemetry.ps1"],
            exit_code=0,
            stdout=json.dumps({
                "procmon": {"started": True, "pid": 1234},
                "tshark": {"started": True, "pid": 5678},
                "regshot": {"started": False, "error": "Regshot not installed"}
            })
        )
        rec = self.backend.start_telemetry()
        self.assertEqual(rec.status, ActionStatus.PARTIAL.value)

    # =========================================================================
    # Requirement 3: Execution Status Semantics
    # =========================================================================
    @patch("sandbox.backends.virtualbox.VirtualBoxSandboxBackend._run_guest_ps_script")
    def test_execute_status_start_failed(self, mock_script):
        """When guest launch fails, execute returns FAILED with START_FAILED."""
        mock_script.return_value = make_exec_result(
            ["guestcontrol", "run", "execute_sample.ps1"],
            exit_code=1,
            stdout=json.dumps({"status": "START_FAILED", "error": "Binary not executable"})
        )
        rec = self.backend.execute(r"C:\0206\work\sample.exe")
        self.assertFalse(rec.is_success())
        self.assertEqual(rec.status, ActionStatus.FAILED.value)
        self.assertIn("START_FAILED", rec.details)

    @patch("sandbox.backends.virtualbox.VirtualBoxSandboxBackend._run_guest_ps_script")
    def test_execute_status_timeout_is_never_success(self, mock_script):
        """Host-side VBoxManage timeout must NOT report SUCCESS."""
        mock_script.return_value = make_exec_result(
            ["guestcontrol", "run", "execute_sample.ps1"],
            exit_code=1,
            timed_out=True,
            stderr="Command timed out after 30s"
        )
        rec = self.backend.execute(r"C:\0206\work\sample.exe")
        self.assertFalse(rec.is_success())
        self.assertEqual(rec.status, ActionStatus.FAILED.value)
        self.assertIn("TIMED_OUT", rec.details)

    @patch("sandbox.backends.virtualbox.VirtualBoxSandboxBackend._run_guest_ps_script")
    def test_execute_status_exited_success(self, mock_script):
        """When guest process cleanly exits, execute returns SUCCESS with EXITED and PID."""
        mock_script.return_value = make_exec_result(
            ["guestcontrol", "run", "execute_sample.ps1"],
            exit_code=0,
            stdout=json.dumps({"status": "EXITED", "pid": 4321, "exit_code": 0})
        )
        rec = self.backend.execute(r"C:\0206\work\sample.exe")
        self.assertTrue(rec.is_success())
        self.assertEqual(rec.status, ActionStatus.SUCCESS.value)
        self.assertIn("EXITED", rec.details)
        self.assertIn("4321", rec.details)

    # =========================================================================
    # Requirement 6: Strong Network Verification
    # =========================================================================
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

    # =========================================================================
    # Requirement 9: Two-Stage Truthful Sandbox Doctor
    # =========================================================================
    def test_sandbox_doctor_two_stage_healthy(self):
        """Doctor must run both HOST_PREFLIGHT and harmless GUEST_PREFLIGHT."""
        fake_vbox = self._create_fake_vboxmanage(Path(self.tmp_dir.name))
        backend = VirtualBoxSandboxBackend(self.config, vbox_bin=str(fake_vbox))
        backend.is_available = MagicMock(return_value=True)

        console = Console(file=io.StringIO())
        healthy = run_sandbox_doctor(console, "virtualbox", self.config, backend_instance=backend)
        self.assertTrue(healthy)

    @patch("shutil.which")
    @patch("sandbox.backends.virtualbox.SafeProcessGuard.run")
    def test_sandbox_doctor_fails_when_host_preflight_fails(self, mock_run, mock_which):
        """Doctor must fail early and never boot guest when VM is missing."""
        mock_which.return_value = "/usr/bin/VBoxManage"
        mock_run.return_value = make_exec_result(
            ["/usr/bin/VBoxManage", "showvminfo", "test_analysis_vm", "--machinereadable"],
            exit_code=1,
            stderr="VBOX_E_OBJECT_NOT_FOUND"
        )
        console = Console(file=io.StringIO())
        healthy = run_sandbox_doctor(console, "virtualbox", self.config)
        self.assertFalse(healthy)
        # Verify startvm was NEVER called
        for call in mock_run.call_args_list:
            self.assertNotIn("startvm", call[0][0])

    # =========================================================================
    # Requirement 13: TOML Config Loading
    # =========================================================================
    def test_sandbox_config_toml_loading(self):
        """TOML configuration loading for non-default VM parameters."""
        toml_content = """
vm_name = "win11-isolated-vm"
snapshot_name = "clean_baseline_snap"
guest_username = "sandbox_analyst"
guest_password_env = "MY_VM_PASS"
network_mode = "ISOLATED"
execution_timeout = 45
vbox_user_home = "/opt/virtualbox/config"
require_procmon = true
require_pcap = true
require_regshot = false
"""
        toml_path = Path(self.tmp_dir.name) / "custom_config.toml"
        toml_path.write_text(toml_content, encoding="utf-8")

        loaded_cfg = SandboxGuestConfig.load_config(str(toml_path))
        self.assertEqual(loaded_cfg.vm_name, "win11-isolated-vm")
        self.assertEqual(loaded_cfg.snapshot_name, "clean_baseline_snap")
        self.assertEqual(loaded_cfg.guest_username, "sandbox_analyst")
        self.assertEqual(loaded_cfg.guest_password_env, "MY_VM_PASS")
        self.assertEqual(loaded_cfg.network_mode, SandboxNetworkMode.ISOLATED)
        self.assertEqual(loaded_cfg.execution_timeout, 45)
        self.assertEqual(loaded_cfg.vbox_user_home, "/opt/virtualbox/config")
        self.assertTrue(loaded_cfg.require_procmon)
        self.assertFalse(loaded_cfg.require_regshot)


if __name__ == "__main__":
    unittest.main()
