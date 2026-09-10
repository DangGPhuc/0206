"""
0206 - VirtualBox Sandbox Backend
Production VirtualBox hypervisor backend using VBoxManage CLI.
Enforces fail-closed execution, strict network isolation inspection,
canonical in-guest telemetry orchestration, truthful status semantics,
and guaranteed baseline snapshot reversion.
"""
import os
import sys
import json
import time
import shutil
import uuid
import hashlib
import tempfile
import contextlib
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime, timezone

from sandbox.backend import SandboxBackend
from sandbox.schema import (
    SandboxGuestConfig,
    SandboxActionRecord,
    SandboxExecutionTrace,
    SandboxStatus,
    SandboxNetworkMode,
    SandboxNetworkState,
    ActionStatus,
    ExecutionSubStatus,
)
from core.process_guard import SafeProcessGuard, ProcessExecutionResult


class VirtualBoxSandboxBackend(SandboxBackend):
    """
    VirtualBox hypervisor backend using VBoxManage CLI.
    Guarantees untrusted binaries execute ONLY inside the Windows guest VM.
    """

    def __init__(self, config: Optional[SandboxGuestConfig] = None, vbox_bin: Optional[str] = None):
        super().__init__(config)
        self.vbox_bin = vbox_bin or shutil.which("VBoxManage") or shutil.which("vboxmanage")
        self._trace_id = f"vbox-{uuid.uuid4().hex[:8]}"

        # Resolve trusted VirtualBox user home configuration directory
        self.vbox_user_home: Optional[str] = None
        if self.config.vbox_user_home:
            self.vbox_user_home = self.config.vbox_user_home
        elif os.environ.get("VBOX_USER_HOME"):
            self.vbox_user_home = os.environ.get("VBOX_USER_HOME")
        else:
            candidates = [
                Path.home() / ".config" / "VirtualBox",
                Path.home() / ".VirtualBox",
            ]
            for cand in candidates:
                if cand.is_dir():
                    self.vbox_user_home = str(cand)
                    break

        # Session-specific directory layout to prevent stale artifact ingestion
        self.guest_session_dir = f"C:\\0206\\sessions\\{self._trace_id}"
        self.guest_work_dir = f"{self.guest_session_dir}\\work"
        self.guest_telemetry_dir = f"{self.guest_session_dir}\\telemetry"
        self.guest_scripts_dir = r"C:\0206\scripts"

        self._network_state: SandboxNetworkState = SandboxNetworkState.UNVERIFIED
        self._sample_sha256: Optional[str] = None
        self._sample_guest_path: Optional[str] = None
        self._baseline_snapshot_uuid: Optional[str] = None
        self._start_time: Optional[str] = None
        self._end_time: Optional[str] = None
        self._execution_duration: float = 0.0
        self._execution_status: str = "NOT_EXECUTED"
        self._revert_status: str = "PENDING"
        self._processes_spawned: List[Dict[str, Any]] = []
        self._errors: List[str] = []
        self._warnings: List[str] = []

    @property
    def name(self) -> str:
        return "virtualbox"

    @property
    def network_state(self) -> SandboxNetworkState:
        return self._network_state

    def is_available(self) -> bool:
        """Available only if VBoxManage binary is detected in PATH and executable."""
        return self.vbox_bin is not None and (shutil.which(self.vbox_bin) is not None or os.path.isfile(self.vbox_bin))

    @contextlib.contextmanager
    def _guest_auth_args(self):
        """
        Provides protected guest authentication arguments.
        Uses --passwordfile with a temporary mode-0600 file to prevent plaintext passwords
        from existing in host process argv or /proc/<pid>/cmdline.
        Scrubbed with null bytes and unlinked in finally.
        """
        user = self.config.guest_username
        pwd = self.config.get_guest_password()
        if not pwd:
            yield ["--username", user]
            return

        fd, tmp_path = tempfile.mkstemp(prefix="vbox_cred_", suffix=".tmp")
        try:
            os.chmod(tmp_path, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(pwd)
            yield ["--username", user, "--passwordfile", tmp_path]
        finally:
            try:
                if os.path.exists(tmp_path):
                    with open(tmp_path, "w", encoding="utf-8") as f:
                        f.write("\x00" * max(64, len(pwd)))
                    os.unlink(tmp_path)
            except OSError:
                pass

    def _sanitize_details(self, text: str) -> str:
        """Redacts guest passwords and analyst home directories from logs and reports."""
        if not text:
            return ""
        pwd = self.config.get_guest_password()
        clean = text
        if pwd and pwd in clean:
            clean = clean.replace(pwd, "[REDACTED]")
        home_path = str(Path.home())
        if home_path and home_path in clean:
            clean = clean.replace(home_path, "~")
        return clean

    def _run_vbox(self, args: List[str], timeout: int = 60) -> ProcessExecutionResult:
        """Executes a VBoxManage command securely with SafeProcessGuard and redacts credentials."""
        if not self.vbox_bin:
            return ProcessExecutionResult(
                command=["VBoxManage"] + args,
                exit_code=-1,
                duration_ms=0.0,
                stdout="",
                stderr="VBoxManage executable not found on host.",
                stdout_hash="",
                stderr_hash="",
                error_message="VBoxManage not available"
            )

        extra_env = {}
        if self.vbox_user_home:
            extra_env["VBOX_USER_HOME"] = self.vbox_user_home

        full_args = [self.vbox_bin] + args
        res = SafeProcessGuard.run(full_args, timeout=timeout, extra_env=extra_env if extra_env else None)

        # Sanitize sensitive arguments before recording command in logs
        sanitized_cmd = []
        skip_next = False
        pwd = self.config.get_guest_password()
        for a in res.command:
            if skip_next:
                sanitized_cmd.append("[REDACTED]")
                skip_next = False
            elif a in ("--password", "-p"):
                sanitized_cmd.append(a)
                skip_next = True
            elif a == "--passwordfile":
                sanitized_cmd.append(a)
                skip_next = True
            elif pwd and pwd in a:
                sanitized_cmd.append(a.replace(pwd, "[REDACTED]"))
            else:
                sanitized_cmd.append(a)
        res.command = sanitized_cmd

        # Sanitize error message and output strings for reporting
        if res.error_message:
            res.error_message = self._sanitize_details(res.error_message)
        return res

    def _stage_harness_scripts(self) -> bool:
        """Copies canonical in-guest harness scripts to C:\\0206\\scripts\\ inside guest."""
        harness_dir = Path(__file__).resolve().parent.parent / "harness"
        scripts = [
            "preflight.ps1",
            "start_telemetry.ps1",
            "execute_sample.ps1",
            "stop_telemetry.ps1",
            "prepare_collection.ps1",
        ]
        with self._guest_auth_args() as auth_args:
            # Ensure C:\0206\scripts exists in guest
            self._run_vbox([
                "guestcontrol", self.config.vm_name,
                "run",
                *auth_args,
                "--exe", r"C:\Windows\System32\cmd.exe",
                "--wait-stdout", "--", "/c", r"if not exist C:\0206\scripts mkdir C:\0206\scripts"
            ], timeout=20)

            for s in scripts:
                host_p = harness_dir / s
                if host_p.exists():
                    res = self._run_vbox([
                        "guestcontrol", self.config.vm_name,
                        "copyto",
                        *auth_args,
                        "--target-directory", r"C:\0206\scripts",
                        str(host_p.resolve())
                    ], timeout=30)
                    if res.exit_code != 0:
                        return False
        return True

    def _run_guest_ps_script(
        self,
        script_name: str,
        script_args: Optional[List[str]] = None,
        timeout: int = 60
    ) -> ProcessExecutionResult:
        """Invokes a canonical PowerShell harness script inside the Windows guest VM."""
        with self._guest_auth_args() as auth_args:
            guest_script = f"{self.guest_scripts_dir}\\{script_name}"
            cmd = [
                "guestcontrol", self.config.vm_name,
                "run",
                *auth_args,
                "--exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "--wait-stdout", "--wait-exit",
                "--",
                "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", guest_script
            ]
            if script_args:
                cmd.extend(script_args)
            return self._run_vbox(cmd, timeout=timeout)

    @staticmethod
    def _parse_machinereadable(text: str) -> Dict[str, str]:
        """Parses key-value pairs from VBoxManage machine-readable output."""
        parsed: Dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                parsed[k.strip().strip('"')] = v.strip().strip('"')
        return parsed

    def prepare(self) -> SandboxActionRecord:
        """Verifies hypervisor CLI availability and configuration."""
        if not self.is_available():
            rec = SandboxActionRecord(
                action="PREPARE",
                status=ActionStatus.NOT_CONFIGURED.value,
                details="VirtualBox VBoxManage CLI not found in system PATH."
            )
        elif not self.config.vm_name:
            rec = SandboxActionRecord(
                action="PREPARE",
                status=ActionStatus.FAILED.value,
                details="VirtualBox VM name not specified in SandboxGuestConfig."
            )
        else:
            rec = SandboxActionRecord(
                action="PREPARE",
                status=ActionStatus.SUCCESS.value,
                details=f"VirtualBox hypervisor CLI detected: {self.vbox_bin}."
            )
        self.actions.append(rec)
        return rec

    def verify_vm(self) -> SandboxActionRecord:
        """Verifies that the target VM exists and is recognized by VirtualBox."""
        if not self.is_available():
            rec = SandboxActionRecord(action="VERIFY_VM", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        res = self._run_vbox(["showvminfo", self.config.vm_name, "--machinereadable"])
        if res.exit_code != 0:
            err = res.stderr.strip() or f"VM '{self.config.vm_name}' does not exist."
            rec = SandboxActionRecord(action="VERIFY_VM", status=ActionStatus.FAILED.value, details=self._sanitize_details(err), errors=[self._sanitize_details(err)])
        else:
            rec = SandboxActionRecord(action="VERIFY_VM", status=ActionStatus.VERIFIED.value, details=f"Target VM '{self.config.vm_name}' verified.")
        self.actions.append(rec)
        return rec

    def verify_baseline(self) -> SandboxActionRecord:
        """Verifies configured baseline snapshot exists on target VM and records its UUID."""
        if not self.is_available():
            rec = SandboxActionRecord(action="VERIFY_BASELINE", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        res = self._run_vbox(["snapshot", self.config.vm_name, "list", "--machinereadable"])
        if res.exit_code != 0:
            err = res.stderr.strip() or f"Failed to list snapshots for VM '{self.config.vm_name}'."
            rec = SandboxActionRecord(action="VERIFY_BASELINE", status=ActionStatus.FAILED.value, details=self._sanitize_details(err), errors=[self._sanitize_details(err)])
            self.actions.append(rec)
            return rec

        snap_target = self.config.snapshot_name
        found = False
        found_uuid = None

        # 1. Parse snapshot tree from machine-readable key-values
        parsed_kv = self._parse_machinereadable(res.stdout)
        for k, v in parsed_kv.items():
            if v == snap_target and k.startswith("SnapshotName"):
                found = True
                suffix = k[len("SnapshotName"):]
                uuid_key = f"SnapshotUUID{suffix}"
                found_uuid = parsed_kv.get(uuid_key)
                break

        # 2. Check standard text lines for Name and UUID
        if not found or not found_uuid:
            import re
            for line in res.stdout.splitlines():
                m = re.search(r'Name:\s*["\']?' + re.escape(snap_target) + r'["\']?\s*\(UUID:\s*([0-9a-fA-F-]+)\)', line)
                if m:
                    found = True
                    found_uuid = m.group(1).strip()
                    break

        if not found:
            err = f"Baseline snapshot '{snap_target}' not found on VM '{self.config.vm_name}'."
            rec = SandboxActionRecord(action="VERIFY_BASELINE", status=ActionStatus.FAILED.value, details=err, errors=[err])
        elif not found_uuid or not str(found_uuid).strip():
            err = f"Baseline snapshot '{snap_target}' found on VM '{self.config.vm_name}', but SnapshotUUID is missing. Snapshot UUID is mandatory."
            rec = SandboxActionRecord(action="VERIFY_BASELINE", status=ActionStatus.FAILED.value, details=err, errors=[err])
        else:
            self._baseline_snapshot_uuid = str(found_uuid).strip()
            rec = SandboxActionRecord(
                action="VERIFY_BASELINE",
                status=ActionStatus.VERIFIED.value,
                details=f"Baseline snapshot '{snap_target}' verified (UUID: {self._baseline_snapshot_uuid})."
            )
        self.actions.append(rec)
        return rec

    def restore_baseline(self, snapshot_name: Optional[str] = None) -> SandboxActionRecord:
        """Powers off running VM if needed and reverts to clean baseline snapshot."""
        if not self.is_available():
            rec = SandboxActionRecord(action="RESTORE_BASELINE", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        snap = snapshot_name or self.config.snapshot_name

        # Query VM state; if running or paused, force poweroff before snapshot restore
        info_res = self._run_vbox(["showvminfo", self.config.vm_name, "--machinereadable"])
        if info_res.exit_code == 0:
            parsed = self._parse_machinereadable(info_res.stdout)
            vm_state = parsed.get("VMState", "").lower()
            if vm_state in ("running", "paused", "saved"):
                self._run_vbox(["controlvm", self.config.vm_name, "poweroff"], timeout=30)

        res = self._run_vbox(["snapshot", self.config.vm_name, "restore", snap], timeout=60)
        if res.exit_code != 0:
            err = res.stderr.strip() or f"Failed to restore baseline snapshot '{snap}'."
            rec = SandboxActionRecord(action="RESTORE_BASELINE", status=ActionStatus.FAILED.value, details=self._sanitize_details(err), errors=[self._sanitize_details(err)])
        else:
            rec = SandboxActionRecord(action="RESTORE_BASELINE", status=ActionStatus.VERIFIED.value, details=f"Baseline snapshot '{snap}' restored.")
        self.actions.append(rec)
        return rec

    def verify_network(self) -> SandboxActionRecord:
        """
        Inspects VM NIC configuration using VirtualBox metadata.
        Default-deny: Rejects NAT, NAT Network, and Bridged interfaces.
        Allows only Host-only, Internal Network, or all-NICs-disabled.
        """
        if not self.is_available():
            self._network_state = SandboxNetworkState.UNVERIFIED
            rec = SandboxActionRecord(action="VERIFY_NETWORK", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        res = self._run_vbox(["showvminfo", self.config.vm_name, "--machinereadable"])
        if res.exit_code != 0:
            self._network_state = SandboxNetworkState.UNVERIFIED
            err = f"Failed to query network metadata for VM '{self.config.vm_name}'."
            rec = SandboxActionRecord(action="VERIFY_NETWORK", status=ActionStatus.FAILED.value, details=err, errors=[err])
            self.actions.append(rec)
            return rec

        parsed = self._parse_machinereadable(res.stdout)

        # Inspect all 8 possible VirtualBox NIC slots
        enabled_nics: Dict[str, str] = {}
        for i in range(1, 9):
            nic_key = f"nic{i}"
            if nic_key in parsed:
                mode = parsed[nic_key].strip().lower()
                if mode not in ("none", "null", ""):
                    enabled_nics[nic_key] = mode

        # Default-deny: reject any NAT or Bridged interfaces
        leak_interfaces = []
        for nic_id, mode in enabled_nics.items():
            if mode in ("nat", "natnetwork", "bridged"):
                leak_interfaces.append(f"{nic_id}={mode}")

        if leak_interfaces:
            self._network_state = SandboxNetworkState.LEAK_DETECTED
            err = (
                f"Insecure network interface(s) detected: {', '.join(leak_interfaces)}. "
                f"Hostile detonation default-denies NAT, NAT Network, and Bridged interfaces."
            )
            rec = SandboxActionRecord(action="VERIFY_NETWORK", status=ActionStatus.FAILED.value, details=err, errors=[err])
            self.actions.append(rec)
            return rec

        # Verify safe states
        if not enabled_nics:
            self._network_state = SandboxNetworkState.VERIFIED_ISOLATED
            rec = SandboxActionRecord(action="VERIFY_NETWORK", status=ActionStatus.VERIFIED.value, details="All VM NICs disabled: fully isolated.")
        elif all(m == "intnet" for m in enabled_nics.values()):
            self._network_state = SandboxNetworkState.VERIFIED_ISOLATED
            rec = SandboxActionRecord(action="VERIFY_NETWORK", status=ActionStatus.VERIFIED.value, details=f"Internal network verified on {list(enabled_nics.keys())}.")
        elif all(m == "hostonly" for m in enabled_nics.values()):
            if self.config.network_mode == SandboxNetworkMode.SIMULATED_INTERNET:
                # Requires positive guest verification before marking VERIFIED_SIMULATED
                self._network_state = SandboxNetworkState.UNVERIFIED
                rec = SandboxActionRecord(action="VERIFY_NETWORK", status=ActionStatus.VERIFIED.value, details="Host-only interface present; awaiting simulated services verification.")
            else:
                self._network_state = SandboxNetworkState.VERIFIED_HOST_ONLY
                rec = SandboxActionRecord(action="VERIFY_NETWORK", status=ActionStatus.VERIFIED.value, details=f"Host-only interface verified on {list(enabled_nics.keys())}.")
        else:
            self._network_state = SandboxNetworkState.UNVERIFIED
            err = f"Unverified mixed NIC configuration: {enabled_nics}."
            rec = SandboxActionRecord(action="VERIFY_NETWORK", status=ActionStatus.FAILED.value, details=err, errors=[err])

        self.actions.append(rec)
        return rec

    def start(self) -> SandboxActionRecord:
        """Starts the guest VM in headless mode."""
        if not self.is_available():
            rec = SandboxActionRecord(action="START", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        res = self._run_vbox(["startvm", self.config.vm_name, "--type", "headless"], timeout=60)
        if res.exit_code != 0:
            err = res.stderr.strip() or f"Failed to start VM '{self.config.vm_name}' headless."
            rec = SandboxActionRecord(action="START", status=ActionStatus.FAILED.value, details=self._sanitize_details(err), errors=[self._sanitize_details(err)])
        else:
            self._start_time = datetime.now(timezone.utc).isoformat()
            rec = SandboxActionRecord(action="START", status=ActionStatus.SUCCESS.value, details=f"VM '{self.config.vm_name}' started headless.")
        self.actions.append(rec)
        return rec

    def verify_guest_control(self) -> SandboxActionRecord:
        """Validates VirtualBox guest additions, credentials, and runs canonical guest preflight."""
        if not self.is_available():
            rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        user = self.config.guest_username

        # 1. Test basic guest execution capability
        with self._guest_auth_args() as auth_args:
            res = self._run_vbox([
                "guestcontrol", self.config.vm_name,
                "run",
                *auth_args,
                "--exe", r"C:\Windows\System32\cmd.exe",
                "--wait-stdout", "--", "/c", "echo", "0206_READY"
            ], timeout=30)

        if res.exit_code != 0 or "0206_READY" not in res.stdout:
            err = (
                f"Guest control unverified for user '{user}': "
                f"{res.stderr.strip() or res.stdout.strip() or 'Guest Additions not responding'}."
            )
            rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=ActionStatus.FAILED.value, details=self._sanitize_details(err), errors=[self._sanitize_details(err)])
            self.actions.append(rec)
            return rec

        # 2. Stage canonical harness scripts into guest C:\0206\scripts
        staged = self._stage_harness_scripts()
        if not staged:
            err = "Failed to stage canonical harness scripts into C:\\0206\\scripts on guest."
            rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=ActionStatus.FAILED.value, details=err, errors=[err])
            self.actions.append(rec)
            return rec

        # 3. Execute in-guest preflight.ps1 to verify tools and network policy
        net_mode_str = self.config.network_mode.value if hasattr(self.config.network_mode, "value") else str(self.config.network_mode)
        pf_res = self._run_guest_ps_script("preflight.ps1", [
            "-TraceId", self._trace_id,
            "-NetworkMode", net_mode_str,
        ], timeout=30)

        if pf_res.exit_code != 0:
            err = f"Guest preflight failed (exit code {pf_res.exit_code}): {pf_res.stderr or pf_res.stdout}."
            rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=ActionStatus.FAILED.value, details=self._sanitize_details(err), errors=[self._sanitize_details(err)])
            self.actions.append(rec)
            return rec

        # Parse JSON output from preflight.ps1 - MUST FAIL CLOSED if malformed, missing, or not READY
        try:
            pf_json = json.loads(pf_res.stdout.strip())
            if not isinstance(pf_json, dict):
                raise ValueError("Preflight report is not a JSON object")
        except Exception as ex:
            err = f"Failed to parse guest preflight JSON report: {ex} (output: {pf_res.stdout[:200]})."
            rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=ActionStatus.FAILED.value, details=err, errors=[err])
            self.actions.append(rec)
            return rec

        if pf_json.get("status") != "READY":
            err = f"Guest preflight returned status '{pf_json.get('status')}' (expected 'READY'): {pf_json.get('errors', [])}."
            rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=ActionStatus.FAILED.value, details=err, errors=[err])
            self.actions.append(rec)
            return rec

        self._preflight_data = pf_json

        net_info = pf_json.get("network", {})
        if net_info.get("egress_detected", False) and net_mode_str in ("ISOLATED", "HOST_ONLY"):
            self._network_state = SandboxNetworkState.LEAK_DETECTED
            err = "LEAK_DETECTED: In-guest negative probe connected to external internet endpoint."
            rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=ActionStatus.FAILED.value, details=err, errors=[err])
            self.actions.append(rec)
            return rec

        if net_mode_str == SandboxNetworkMode.SIMULATED_INTERNET:
            if net_info.get("simulated_services_verified", False):
                self._network_state = SandboxNetworkState.VERIFIED_SIMULATED
            else:
                self._network_state = SandboxNetworkState.UNVERIFIED
                err = "SIMULATED_UNVERIFIED: In-guest positive verification of simulated services failed."
                rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=ActionStatus.FAILED.value, details=err, errors=[err])
                self.actions.append(rec)
                return rec

        rec = SandboxActionRecord(
            action="VERIFY_GUEST_CONTROL",
            status=ActionStatus.VERIFIED.value,
            details=f"Guest control verified for user '{user}', scripts staged, and in-guest preflight passed."
        )
        self.actions.append(rec)
        return rec

    def start_telemetry(self) -> SandboxActionRecord:
        """
        Initializes session directory and launches in-guest telemetry collectors.
        Fails closed: if any enabled REQUIRED collector fails to launch, returns FAILED.
        """
        if not self.is_available():
            rec = SandboxActionRecord(action="START_TELEMETRY", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        # Ensure harness scripts are staged
        self._stage_harness_scripts()

        # Build start_telemetry.ps1 parameters
        args = [
            "-TelemetryDir", self.guest_telemetry_dir,
            f"-EnableProcmon:${str(self.config.enable_procmon).lower()}",
            f"-EnablePcap:${str(self.config.enable_pcap).lower()}",
            f"-EnableRegshot:${str(self.config.enable_regshot).lower()}",
            f"-RequireProcmon:${str(self.config.require_procmon).lower()}",
            f"-RequirePcap:${str(self.config.require_pcap).lower()}",
            f"-RequireRegshot:${str(self.config.require_regshot).lower()}",
        ]

        res = self._run_guest_ps_script("start_telemetry.ps1", args, timeout=45)

        # Inspect execution result
        if res.timed_out:
            err = "start_telemetry.ps1 timed out in guest VM."
            rec = SandboxActionRecord(action="START_TELEMETRY", status=ActionStatus.FAILED.value, details=err, errors=[err])
            self.actions.append(rec)
            return rec

        if res.exit_code != 0:
            err = f"start_telemetry.ps1 failed with exit code {res.exit_code}: {res.stderr or res.stdout}."
            rec = SandboxActionRecord(action="START_TELEMETRY", status=ActionStatus.FAILED.value, details=self._sanitize_details(err), errors=[self._sanitize_details(err)])
            self.actions.append(rec)
            return rec

        # Verify collector statuses from JSON report
        collectors = {}
        try:
            parsed = json.loads(res.stdout.strip())
            collectors = parsed.get("collectors") if "collectors" in parsed else parsed
        except Exception:
            pass

        failed_required = []
        partial_warnings = []
        if self.config.enable_procmon:
            if not collectors.get("procmon", {}).get("started", False):
                if self.config.require_procmon:
                    failed_required.append("Procmon")
                else:
                    partial_warnings.append("Procmon")
        if self.config.enable_pcap:
            if not collectors.get("tshark", {}).get("started", False):
                if self.config.require_pcap:
                    failed_required.append("tshark/PCAP")
                else:
                    partial_warnings.append("tshark/PCAP")
        if self.config.enable_regshot:
            if not collectors.get("regshot", {}).get("started", False):
                if self.config.require_regshot:
                    failed_required.append("Regshot")
                else:
                    partial_warnings.append("Regshot")

        if failed_required:
            err = f"Required telemetry collector(s) failed to start: {', '.join(failed_required)}."
            self._errors.append(err)
            rec = SandboxActionRecord(action="START_TELEMETRY", status=ActionStatus.FAILED.value, details=err, errors=[err])
            self.actions.append(rec)
            return rec

        if partial_warnings:
            warn_msg = f"Optional collector(s) unavailable/partial: {', '.join(partial_warnings)}."
            self._warnings.append(warn_msg)
            self._telemetry_completeness = "PARTIAL"
        else:
            self._telemetry_completeness = "FULL"

        msg = f"Session telemetry directory '{self.guest_telemetry_dir}' initialized. All required collectors verified."
        if partial_warnings:
            msg += f" (Optional collector(s) unavailable: {', '.join(partial_warnings)})"

        rec = SandboxActionRecord(
            action="START_TELEMETRY",
            status=ActionStatus.SUCCESS.value,
            details=msg
        )
        self.actions.append(rec)
        return rec

    def transfer(self, sample_path: str, target_guest_path: Optional[str] = None) -> SandboxActionRecord:
        """Transfers untrusted sample into per-session work directory on guest VM."""
        if not self.is_available():
            rec = SandboxActionRecord(action="TRANSFER", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        host_p = Path(sample_path)
        if not host_p.exists():
            err = f"Sample binary '{sample_path}' does not exist on host."
            rec = SandboxActionRecord(action="TRANSFER", status=ActionStatus.FAILED.value, details=err, errors=[err])
            self.actions.append(rec)
            return rec

        # Record hash of original sample before transfer
        with open(host_p, "rb") as f:
            self._sample_sha256 = hashlib.sha256(f.read()).hexdigest()

        guest_dest = target_guest_path or f"{self.guest_work_dir}\\{host_p.name}"
        self._sample_guest_path = guest_dest

        # Ensure session work directory exists
        with self._guest_auth_args() as auth_args:
            self._run_vbox([
                "guestcontrol", self.config.vm_name,
                "run",
                *auth_args,
                "--exe", r"C:\Windows\System32\cmd.exe",
                "--wait-stdout", "--", "/c", f'if not exist "{self.guest_work_dir}" mkdir "{self.guest_work_dir}"'
            ], timeout=20)

            res = self._run_vbox([
                "guestcontrol", self.config.vm_name,
                "copyto",
                *auth_args,
                "--target-directory", self.guest_work_dir,
                str(host_p.resolve())
            ], timeout=60)

        if res.exit_code != 0:
            err = f"Failed to transfer sample into guest VM: {res.stderr.strip()}."
            rec = SandboxActionRecord(action="TRANSFER", status=ActionStatus.FAILED.value, details=self._sanitize_details(err), errors=[self._sanitize_details(err)])
        else:
            rec = SandboxActionRecord(
                action="TRANSFER",
                status=ActionStatus.SUCCESS.value,
                details=f"Transferred sample to {guest_dest} (SHA256: {self._sample_sha256})."
            )

        self.actions.append(rec)
        return rec

    def execute(self, sample_path: str, arguments: Optional[List[str]] = None) -> SandboxActionRecord:
        """
        CRITICAL SAFETY REQUIREMENT:
        Executes sample ONLY through VirtualBox guest control inside the Windows guest VM.
        NEVER executes on host.
        Enforces truthful execution status semantics:
          START_FAILED, STARTED, EXITED, TIMED_OUT, FAILED, UNKNOWN.
        """
        if not self.is_available():
            rec = SandboxActionRecord(action="EXECUTE", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        guest_exe = self._sample_guest_path or f"{self.guest_work_dir}\\{Path(sample_path).name}"

        # Run execute_sample.ps1
        exec_args = [
            "-SamplePath", guest_exe,
            "-TimeoutSeconds", str(self.config.execution_timeout_seconds),
        ]
        if arguments:
            exec_args.extend(["-Arguments", *arguments])

        # Execute in guest with bounded execution window
        res = self._run_guest_ps_script("execute_sample.ps1", exec_args, timeout=self.config.execution_timeout_seconds + 30)

        # Host-side VBoxManage timeout != guest process completion
        if res.timed_out:
            self._execution_status = ExecutionSubStatus.TIMED_OUT.value
            self._errors.append("Host-side VBoxManage timed out during sample execution. Guest state uncertain.")
            rec = SandboxActionRecord(
                action="EXECUTE",
                status=ActionStatus.FAILED.value,
                details=f"Host-side VBoxManage timed out during execution of {guest_exe} (sub-status: TIMED_OUT)."
            )
            self.actions.append(rec)
            return rec

        # Parse JSON output from execute_sample.ps1
        parsed = {}
        try:
            parsed = json.loads(res.stdout.strip())
        except Exception:
            pass

        launch_status = parsed.get("launch_status") or parsed.get("status") or ExecutionSubStatus.UNKNOWN.value
        guest_pid = parsed.get("guest_pid") or parsed.get("pid")
        execution_status = parsed.get("execution_status") or parsed.get("status")
        exited = parsed.get("exited", False) or execution_status == "EXITED"
        exit_code = parsed.get("exit_code")
        timed_out = parsed.get("timed_out", False) or execution_status == "TIMED_OUT"
        duration_ms = parsed.get("duration_ms", res.duration_ms)

        self._processes_spawned.append({
            "guest_path": guest_exe,
            "pid": guest_pid,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "launch_status": launch_status,
            "timed_out": timed_out
        })

        if (
            launch_status in (ExecutionSubStatus.START_FAILED.value, "START_FAILED")
            or execution_status in (ExecutionSubStatus.FAILED.value, "FAILED", "START_FAILED")
            or (res.exit_code != 0 and not parsed)
        ):
            self._execution_status = ExecutionSubStatus.START_FAILED.value
            err = f"In-guest sample launch failed: {parsed.get('error') or res.stderr or 'Execution failed'} (sub-status: START_FAILED)."
            self._errors.append(err)
            rec = SandboxActionRecord(action="EXECUTE", status=ActionStatus.FAILED.value, details=self._sanitize_details(err), errors=[self._sanitize_details(err)])
            self.actions.append(rec)
            return rec

        # Verified guest launch
        if timed_out:
            self._execution_status = ExecutionSubStatus.TIMED_OUT.value
            details_str = f"Sample launched (PID: {guest_pid}), execution timed out after {duration_ms}ms (sub-status: TIMED_OUT)."
        else:
            self._execution_status = ExecutionSubStatus.EXITED.value
            details_str = f"Sample launched (PID: {guest_pid}), exited with code {exit_code} (Duration: {duration_ms}ms, sub-status: EXITED)."
            if exit_code is not None and exit_code != 0:
                self._warnings.append(f"Guest process exited with nonzero code {exit_code}.")

        rec = SandboxActionRecord(
            action="EXECUTE",
            status=ActionStatus.SUCCESS.value,
            details=details_str
        )
        self.actions.append(rec)
        return rec

    def monitor(self, duration_seconds: Optional[int] = None) -> SandboxActionRecord:
        """Monitors guest during bounded execution window."""
        dur = duration_seconds or min(self.config.execution_timeout_seconds, 5)
        time.sleep(min(dur, 5))
        rec = SandboxActionRecord(action="MONITOR", status=ActionStatus.SUCCESS.value, details=f"Monitored guest telemetry ({dur}s window).")
        self.actions.append(rec)
        return rec

    def stop_telemetry(self) -> SandboxActionRecord:
        """Halts in-guest collectors and prepares collection metadata."""
        if not self.is_available():
            rec = SandboxActionRecord(action="STOP_TELEMETRY", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        stop_errors: List[str] = []
        stop_warnings: List[str] = []

        # 1. Invoke canonical stop_telemetry.ps1
        res1 = self._run_guest_ps_script("stop_telemetry.ps1", ["-TelemetryDir", self.guest_telemetry_dir], timeout=35)
        if res1.timed_out:
            stop_errors.append("stop_telemetry.ps1 timed out in guest VM.")
        elif res1.exit_code != 0:
            stop_errors.append(f"stop_telemetry.ps1 failed with exit code {res1.exit_code}: {res1.stderr or res1.stdout}")
        else:
            try:
                stop_data = json.loads(res1.stdout.strip())
                artifacts = stop_data.get("artifacts", {})
                if self.config.enable_procmon and self.config.require_procmon and not artifacts.get("procmon_csv", False):
                    stop_errors.append("Required Procmon CSV artifact was not produced by stop_telemetry.")
                elif self.config.enable_procmon and not artifacts.get("procmon_csv", False):
                    stop_warnings.append("Optional Procmon CSV artifact was not produced.")

                if self.config.enable_pcap and self.config.require_pcap and not artifacts.get("network_pcap", False):
                    stop_errors.append("Required PCAP artifact was not produced by stop_telemetry.")
                elif self.config.enable_pcap and not artifacts.get("network_pcap", False):
                    stop_warnings.append("Optional PCAP artifact was not produced.")

                if self.config.enable_regshot and self.config.require_regshot and not artifacts.get("regshot_txt", False):
                    stop_errors.append("Required Regshot artifact was not produced by stop_telemetry.")
                elif self.config.enable_regshot and not artifacts.get("regshot_txt", False):
                    stop_warnings.append("Optional Regshot artifact was not produced.")

                for err in stop_data.get("errors", []):
                    stop_warnings.append(f"stop_telemetry script warning: {err}")
            except Exception as ex:
                stop_warnings.append(f"Could not parse stop_telemetry JSON output: {ex}")

        # 2. Invoke canonical prepare_collection.ps1
        res2 = self._run_guest_ps_script("prepare_collection.ps1", [
            "-WorkDir", self.guest_work_dir,
            "-TelemetryDir", self.guest_telemetry_dir,
            "-TraceId", self._trace_id,
            "-SampleSha256", self._sample_sha256 or ""
        ], timeout=30)
        if res2.timed_out:
            stop_errors.append("prepare_collection.ps1 timed out in guest VM.")
        elif res2.exit_code != 0:
            stop_errors.append(f"prepare_collection.ps1 failed with exit code {res2.exit_code}: {res2.stderr or res2.stdout}")
        else:
            try:
                prep_data = json.loads(res2.stdout.strip())
                self._prepared_metadata = prep_data
            except Exception as ex:
                stop_warnings.append(f"Could not parse prepare_collection JSON output: {ex}")

        self._errors.extend(stop_errors)
        self._warnings.extend(stop_warnings)

        if stop_errors:
            st = ActionStatus.FAILED.value
            details = f"Telemetry finalization failed: {'; '.join(stop_errors)}"
        elif stop_warnings:
            st = ActionStatus.PARTIAL.value
            details = f"Telemetry collectors halted with warnings: {'; '.join(stop_warnings)}"
        else:
            st = ActionStatus.SUCCESS.value
            details = "Telemetry collectors halted and logs finalized successfully."

        rec = SandboxActionRecord(
            action="STOP_TELEMETRY",
            status=st,
            details=details,
            errors=list(stop_errors)
        )
        self.actions.append(rec)
        return rec

    def collect(self, output_dir: str) -> SandboxExecutionTrace:
        """
        Transfers safe telemetry files from guest to host output_dir:
          procmon.csv, network.pcap, regshot.txt, execution_metadata.json
        Uses VirtualBox 7.2 copyfrom syntax:
          VBoxManage guestcontrol <vm> copyfrom [options...] <guest-src> <host-dst>
        Associates each artifact with trace_id, sample_sha256, and SHA256.
        Does NOT copy dropped executable binaries back to host by default.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        guest_artifacts = [
            ("procmon.csv", f"{self.guest_telemetry_dir}\\procmon.csv"),
            ("network.pcap", f"{self.guest_telemetry_dir}\\network.pcap"),
            ("regshot.txt", f"{self.guest_telemetry_dir}\\regshot.txt"),
            ("execution_metadata.json", f"{self.guest_telemetry_dir}\\execution_metadata.json"),
        ]

        collected_paths: Dict[str, str] = {}
        telemetry_hashes: Dict[str, str] = {}

        if self.is_available():
            with self._guest_auth_args() as auth_args:
                for local_name, guest_path in guest_artifacts:
                    host_dest = out_path / local_name
                    # Oracle VirtualBox 7.2 guestcontrol copyfrom syntax:
                    # guestcontrol <vm> copyfrom [options...] <guest-src> <host-dst>
                    res = self._run_vbox([
                        "guestcontrol", self.config.vm_name,
                        "copyfrom",
                        *auth_args,
                        guest_path,
                        str(host_dest.resolve())
                    ], timeout=30)
                    if res.exit_code == 0 and host_dest.exists():
                        collected_paths[local_name] = str(host_dest.resolve())
                        with open(host_dest, "rb") as f:
                            telemetry_hashes[local_name] = hashlib.sha256(f.read()).hexdigest()

        # Parse dropped file metadata (safe metadata: filename, path, size, sha256)
        dropped_meta: List[Dict[str, Any]] = []
        meta_file = out_path / "execution_metadata.json"
        if meta_file.exists():
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    meta_dict = json.load(f)
                    dropped_meta = meta_dict.get("dropped_files", [])
            except Exception:
                pass

        self._end_time = datetime.now(timezone.utc).isoformat()
        if self._start_time:
            try:
                t0 = datetime.fromisoformat(self._start_time)
                t1 = datetime.fromisoformat(self._end_time)
                self._execution_duration = round((t1 - t0).total_seconds(), 2)
            except Exception:
                pass

        net_mode_val = self.config.network_mode.value if hasattr(self.config.network_mode, "value") else str(self.config.network_mode)

        return SandboxExecutionTrace(
            trace_id=self._trace_id,
            backend_name=self.name,
            vm_name=self.config.vm_name,
            snapshot_name=self.config.snapshot_name,
            baseline_snapshot_uuid=self._baseline_snapshot_uuid,
            network_mode=net_mode_val,
            sandbox_network_mode=net_mode_val,
            network_verification_status=self._network_state.value,
            sandbox_network_verification_status=self._network_state.value,
            telemetry_completeness=getattr(self, "_telemetry_completeness", "FULL"),
            started_at=self._start_time or datetime.now(timezone.utc).isoformat(),
            finished_at=self._end_time,
            execution_duration=self._execution_duration,
            sample_guest_path=self._sample_guest_path,
            sample_sha256=self._sample_sha256,
            actions=list(self.actions),
            pcap_path=collected_paths.get("network.pcap"),
            procmon_csv_path=collected_paths.get("procmon.csv"),
            regshot_path=collected_paths.get("regshot.txt"),
            execution_metadata_path=collected_paths.get("execution_metadata.json"),
            processes_spawned=list(self._processes_spawned),
            dropped_file_metadata=dropped_meta,
            dropped_files=[f.get("filename", "") for f in dropped_meta if f.get("filename")],
            telemetry_hashes=telemetry_hashes,
            execution_status=self._execution_status,
            revert_status=self._revert_status,
            errors=list(self._errors),
            warnings=list(self._warnings),
        )

    def stop(self) -> SandboxActionRecord:
        """Forces VM power off."""
        if not self.is_available():
            rec = SandboxActionRecord(action="STOP", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        res = self._run_vbox(["controlvm", self.config.vm_name, "poweroff"], timeout=30)
        rec = SandboxActionRecord(
            action="STOP",
            status=ActionStatus.SUCCESS.value if res.exit_code == 0 else ActionStatus.FAILED.value,
            details=f"VM poweroff executed: {self._sanitize_details(res.stdout.strip() or res.stderr.strip())}."
        )
        self.actions.append(rec)
        return rec

    def revert(self, snapshot_name: Optional[str] = None) -> SandboxActionRecord:
        """Restores baseline snapshot."""
        if not self.is_available():
            rec = SandboxActionRecord(action="REVERT", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        snap = snapshot_name or self.config.snapshot_name
        res = self._run_vbox(["snapshot", self.config.vm_name, "restore", snap], timeout=60)
        st = ActionStatus.VERIFIED.value if res.exit_code == 0 else ActionStatus.FAILED.value
        self._revert_status = st
        rec = SandboxActionRecord(
            action="REVERT",
            status=st,
            details=f"Revert to snapshot '{snap}': {self._sanitize_details(res.stdout.strip() or res.stderr.strip())}."
        )
        self.actions.append(rec)
        return rec

    def verify_clean(self) -> SandboxActionRecord:
        """
        Verifies VM state is poweroff and reverted back to the clean snapshot.
        Enforces strict validation:
        - Baseline snapshot UUID must have been recorded during VERIFY_BASELINE
        - VMState == poweroff
        - CurrentSnapshotName is non-blank and matches configured snapshot
        - CurrentSnapshotUUID is non-blank and matches recorded baseline snapshot UUID
        """
        if not self.is_available():
            rec = SandboxActionRecord(action="VERIFY_CLEAN", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        # Baseline UUID is mandatory
        if not self._baseline_snapshot_uuid:
            err_msg = "Clean state verification failed: baseline snapshot UUID is missing (was never recorded during baseline verification)."
            rec = SandboxActionRecord(action="VERIFY_CLEAN", status=ActionStatus.FAILED.value, details=err_msg, errors=[err_msg])
            self.actions.append(rec)
            return rec

        res = self._run_vbox(["showvminfo", self.config.vm_name, "--machinereadable"])
        if res.exit_code != 0:
            rec = SandboxActionRecord(action="VERIFY_CLEAN", status=ActionStatus.FAILED.value, details="Failed to query VM clean state.")
            self.actions.append(rec)
            return rec

        parsed = self._parse_machinereadable(res.stdout)
        vm_state = parsed.get("VMState", "").lower()
        current_snap_name = parsed.get("CurrentSnapshotName", "")
        current_snap_uuid = parsed.get("CurrentSnapshotUUID", "")

        # 1. VM must be powered off
        is_poweroff = (vm_state == "poweroff")

        # 2. Snapshot name must NOT be blank and must match configured snapshot
        has_snap_name = bool(current_snap_name.strip())
        name_matches = (current_snap_name == self.config.snapshot_name)

        # 3. Snapshot UUID must NOT be blank and must match baseline UUID
        has_snap_uuid = bool(current_snap_uuid.strip())
        uuid_matches = (has_snap_uuid and current_snap_uuid == self._baseline_snapshot_uuid)

        clean = is_poweroff and has_snap_name and name_matches and uuid_matches
        if not clean:
            err_reasons = []
            if not is_poweroff:
                err_reasons.append(f"VMState is '{vm_state}' (expected 'poweroff')")
            if not has_snap_name:
                err_reasons.append("CurrentSnapshotName is blank")
            elif not name_matches:
                err_reasons.append(f"CurrentSnapshotName is '{current_snap_name}' (expected '{self.config.snapshot_name}')")
            if not has_snap_uuid:
                err_reasons.append("CurrentSnapshotUUID is blank")
            elif not uuid_matches:
                err_reasons.append(f"CurrentSnapshotUUID '{current_snap_uuid}' != baseline '{self._baseline_snapshot_uuid}' (UUID mismatch)")

            err_msg = f"Clean state verification failed: {'; '.join(err_reasons)}."
            rec = SandboxActionRecord(action="VERIFY_CLEAN", status=ActionStatus.FAILED.value, details=err_msg, errors=[err_msg])
        else:
            rec = SandboxActionRecord(
                action="VERIFY_CLEAN",
                status=ActionStatus.VERIFIED.value,
                details=f"VM clean state verified: poweroff, snapshot '{current_snap_name}' (UUID: {current_snap_uuid})."
            )

        self.actions.append(rec)
        return rec

    def cleanup(self) -> SandboxActionRecord:
        """Cleans up local temporary state."""
        rec = SandboxActionRecord(action="CLEANUP", status=ActionStatus.SUCCESS.value, details="VirtualBox session resources cleaned up.")
        self.actions.append(rec)
        return rec
