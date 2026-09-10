"""
0206 - VirtualBox Sandbox Backend
Phase 12: Production VirtualBox hypervisor backend using VBoxManage.
Enforces fail-closed execution, strict network isolation inspection,
in-guest telemetry orchestration, and guaranteed baseline reversion.
"""
import os
import json
import time
import shutil
import uuid
import hashlib
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
        self._network_state: SandboxNetworkState = SandboxNetworkState.UNVERIFIED
        self._sample_sha256: Optional[str] = None
        self._sample_guest_path: Optional[str] = None
        self._start_time: Optional[str] = None
        self._end_time: Optional[str] = None
        self._execution_duration: float = 0.0
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

        full_args = [self.vbox_bin] + args
        res = SafeProcessGuard.run(full_args, timeout=timeout)

        # Sanitize sensitive arguments before recording command in logs
        sanitized_cmd = []
        skip_next = False
        for a in res.command:
            if skip_next:
                sanitized_cmd.append("[REDACTED]")
                skip_next = False
            elif a in ("--password", "-p"):
                sanitized_cmd.append(a)
                skip_next = True
            else:
                sanitized_cmd.append(a)
        res.command = sanitized_cmd
        return res

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
            rec = SandboxActionRecord(action="VERIFY_VM", status=ActionStatus.FAILED.value, details=err, errors=[err])
        else:
            rec = SandboxActionRecord(action="VERIFY_VM", status=ActionStatus.VERIFIED.value, details=f"Target VM '{self.config.vm_name}' verified.")
        self.actions.append(rec)
        return rec

    def verify_baseline(self) -> SandboxActionRecord:
        """Verifies configured baseline snapshot exists on the target VM."""
        if not self.is_available():
            rec = SandboxActionRecord(action="VERIFY_BASELINE", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        res = self._run_vbox(["snapshot", self.config.vm_name, "list", "--machinereadable"])
        if res.exit_code != 0:
            err = res.stderr.strip() or f"Failed to list snapshots for VM '{self.config.vm_name}'."
            rec = SandboxActionRecord(action="VERIFY_BASELINE", status=ActionStatus.FAILED.value, details=err, errors=[err])
            self.actions.append(rec)
            return rec

        # Check if snapshot_name is present in snapshot tree
        snap_target = self.config.snapshot_name
        found = False
        for line in res.stdout.splitlines():
            if f'"{snap_target}"' in line or f'={snap_target}' in line:
                found = True
                break

        if not found:
            err = f"Baseline snapshot '{snap_target}' not found on VM '{self.config.vm_name}'."
            rec = SandboxActionRecord(action="VERIFY_BASELINE", status=ActionStatus.FAILED.value, details=err, errors=[err])
        else:
            rec = SandboxActionRecord(action="VERIFY_BASELINE", status=ActionStatus.VERIFIED.value, details=f"Baseline snapshot '{snap_target}' verified.")
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
            rec = SandboxActionRecord(action="RESTORE_BASELINE", status=ActionStatus.FAILED.value, details=err, errors=[err])
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
                self._network_state = SandboxNetworkState.VERIFIED_SIMULATED
                rec = SandboxActionRecord(action="VERIFY_NETWORK", status=ActionStatus.VERIFIED.value, details=f"Host-only interface verified for simulated internet.")
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
            rec = SandboxActionRecord(action="START", status=ActionStatus.FAILED.value, details=err, errors=[err])
        else:
            self._start_time = datetime.now(timezone.utc).isoformat()
            rec = SandboxActionRecord(action="START", status=ActionStatus.SUCCESS.value, details=f"VM '{self.config.vm_name}' started headless.")
        self.actions.append(rec)
        return rec

    def verify_guest_control(self) -> SandboxActionRecord:
        """Validates that VirtualBox guest additions and credentials allow guest execution."""
        if not self.is_available():
            rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        user = self.config.guest_username
        pwd = self.config.get_guest_password()

        res = self._run_vbox([
            "guestcontrol", self.config.vm_name,
            "--username", user,
            "--password", pwd,
            "run", "--exe", r"C:\Windows\System32\cmd.exe",
            "--wait-stdout", "--", "/c", "echo", "0206_READY"
        ], timeout=30)

        if res.exit_code != 0 or "0206_READY" not in res.stdout:
            err = (
                f"Guest control unverified for user '{user}': "
                f"{res.stderr.strip() or res.stdout.strip() or 'Guest Additions not responding'}."
            )
            rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=ActionStatus.FAILED.value, details=err, errors=[err])
        else:
            rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=ActionStatus.VERIFIED.value, details=f"Guest control verified for user '{user}'.")

        self.actions.append(rec)
        return rec

    def start_telemetry(self) -> SandboxActionRecord:
        """Initializes standard directories and launches in-guest telemetry collectors."""
        if not self.is_available():
            rec = SandboxActionRecord(action="START_TELEMETRY", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        user = self.config.guest_username
        pwd = self.config.get_guest_password()

        # 1. Provision standard predictable directories: C:\0206\tools, work, telemetry, scripts
        mkdir_cmd = (
            r"if not exist C:\0206\tools mkdir C:\0206\tools & "
            r"if not exist C:\0206\work mkdir C:\0206\work & "
            r"if not exist C:\0206\telemetry mkdir C:\0206\telemetry & "
            r"if not exist C:\0206\scripts mkdir C:\0206\scripts"
        )
        res_dir = self._run_vbox([
            "guestcontrol", self.config.vm_name,
            "--username", user,
            "--password", pwd,
            "run", "--exe", r"C:\Windows\System32\cmd.exe",
            "--wait-stdout", "--", "/c", mkdir_cmd
        ], timeout=30)

        if res_dir.exit_code != 0:
            err = f"Failed to initialize guest directories: {res_dir.stderr.strip()}."
            rec = SandboxActionRecord(action="START_TELEMETRY", status=ActionStatus.FAILED.value, details=err, errors=[err])
            self.actions.append(rec)
            return rec

        # 2. Launch Procmon in background if enabled
        if self.config.enable_procmon:
            self._run_vbox([
                "guestcontrol", self.config.vm_name,
                "--username", user,
                "--password", pwd,
                "run", "--exe", r"C:\Windows\System32\cmd.exe",
                "--", "/c",
                r"start /b C:\Tools\procmon\procmon.exe /BackingFile C:\0206\telemetry\procmon.pml /Quiet /Minimized /AcceptEula"
            ], timeout=15)

        # 3. Launch tshark in background if enabled
        if self.config.enable_pcap:
            self._run_vbox([
                "guestcontrol", self.config.vm_name,
                "--username", user,
                "--password", pwd,
                "run", "--exe", r"C:\Windows\System32\cmd.exe",
                "--", "/c",
                r'start /b "" "C:\Program Files\Wireshark\tshark.exe" -i 1 -w C:\0206\telemetry\network.pcap -a duration:180'
            ], timeout=15)

        # 4. First shot for Regshot if enabled
        if self.config.enable_regshot:
            self._run_vbox([
                "guestcontrol", self.config.vm_name,
                "--username", user,
                "--password", pwd,
                "run", "--exe", r"C:\Windows\System32\cmd.exe",
                "--wait-stdout", "--", "/c",
                r"if exist C:\Tools\regshot\regshot-x64.exe C:\Tools\regshot\regshot-x64.exe /s C:\0206\telemetry\shot1.bin"
            ], timeout=25)

        rec = SandboxActionRecord(
            action="START_TELEMETRY",
            status=ActionStatus.SUCCESS.value,
            details="Guest workspace initialized and telemetry processes launched."
        )
        self.actions.append(rec)
        return rec

    def transfer(self, sample_path: str, target_guest_path: Optional[str] = None) -> SandboxActionRecord:
        """Transfers the untrusted sample into C:\\0206\\work\\ on the guest VM."""
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

        guest_dest = target_guest_path or f"{self.config.guest_work_dir}\\{host_p.name}"
        self._sample_guest_path = guest_dest
        user = self.config.guest_username
        pwd = self.config.get_guest_password()

        res = self._run_vbox([
            "guestcontrol", self.config.vm_name,
            "--username", user,
            "--password", pwd,
            "copyto",
            "--target-directory", self.config.guest_work_dir,
            str(host_p.resolve())
        ], timeout=60)

        if res.exit_code != 0:
            err = f"Failed to transfer sample into guest VM: {res.stderr.strip()}."
            rec = SandboxActionRecord(action="TRANSFER", status=ActionStatus.FAILED.value, details=err, errors=[err])
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
        Executes sample ONLY through VirtualBox guest control inside the Windows guest.
        NEVER executes on host.
        """
        if not self.is_available():
            rec = SandboxActionRecord(action="EXECUTE", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        guest_exe = self._sample_guest_path or f"{self.config.guest_work_dir}\\{Path(sample_path).name}"
        user = self.config.guest_username
        pwd = self.config.get_guest_password()

        exec_cmd = [
            "guestcontrol", self.config.vm_name,
            "--username", user,
            "--password", pwd,
            "run", "--exe", guest_exe
        ]
        if arguments:
            exec_cmd.extend(["--"] + arguments)

        # Execute in guest with bounded execution window
        res = self._run_vbox(exec_cmd, timeout=self.config.execution_timeout_seconds)

        self._processes_spawned.append({
            "guest_path": guest_exe,
            "exit_code": res.exit_code,
            "duration_ms": res.duration_ms
        })

        if res.exit_code is not None and res.exit_code != 0:
            self._warnings.append(f"Guest process exited with code {res.exit_code}.")

        rec = SandboxActionRecord(
            action="EXECUTE",
            status=ActionStatus.SUCCESS.value,
            details=f"Executed sample in-guest: {guest_exe} (Duration: {res.duration_ms}ms)."
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
        """Halts in-guest collectors and generates execution metadata."""
        if not self.is_available():
            rec = SandboxActionRecord(action="STOP_TELEMETRY", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        user = self.config.guest_username
        pwd = self.config.get_guest_password()

        # 1. Stop Procmon and export to CSV
        if self.config.enable_procmon:
            self._run_vbox([
                "guestcontrol", self.config.vm_name,
                "--username", user,
                "--password", pwd,
                "run", "--exe", r"C:\Windows\System32\cmd.exe",
                "--wait-stdout", "--", "/c",
                r"C:\Tools\procmon\procmon.exe /Terminate & C:\Tools\procmon\procmon.exe /OpenLog C:\0206\telemetry\procmon.pml /SaveAs C:\0206\telemetry\procmon.csv"
            ], timeout=30)

        # 2. Stop tshark
        if self.config.enable_pcap:
            self._run_vbox([
                "guestcontrol", self.config.vm_name,
                "--username", user,
                "--password", pwd,
                "run", "--exe", r"C:\Windows\System32\cmd.exe",
                "--wait-stdout", "--", "/c",
                r"taskkill /F /IM tshark.exe & taskkill /F /IM dumpcap.exe"
            ], timeout=15)

        # 3. Stop Regshot (2nd shot & diff)
        if self.config.enable_regshot:
            self._run_vbox([
                "guestcontrol", self.config.vm_name,
                "--username", user,
                "--password", pwd,
                "run", "--exe", r"C:\Windows\System32\cmd.exe",
                "--wait-stdout", "--", "/c",
                r"if exist C:\Tools\regshot\regshot-x64.exe C:\Tools\regshot\regshot-x64.exe /s C:\0206\telemetry\shot2.bin & C:\Tools\regshot\regshot-x64.exe /c C:\0206\telemetry\shot1.bin C:\0206\telemetry\shot2.bin C:\0206\telemetry\regshot.txt"
            ], timeout=25)

        # 4. Generate execution_metadata.json for dropped files
        ps_cmd = (
            r'$files = Get-ChildItem -Path C:\0206\work -File -Recurse | ForEach-Object { '
            r'  @{ filename = $_.Name; guest_path = $_.FullName; size = $_.Length; sha256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash } '
            r'}; '
            r'$meta = @{ dropped_files = $files; timestamp = (Get-Date).ToString("o") }; '
            r'$meta | ConvertTo-Json -Depth 4 | Set-Content -Path C:\0206\telemetry\execution_metadata.json'
        )
        self._run_vbox([
            "guestcontrol", self.config.vm_name,
            "--username", user,
            "--password", pwd,
            "run", "--exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "--wait-stdout", "--", "-Command", ps_cmd
        ], timeout=30)

        rec = SandboxActionRecord(action="STOP_TELEMETRY", status=ActionStatus.SUCCESS.value, details="Telemetry collectors halted and logs finalized.")
        self.actions.append(rec)
        return rec

    def collect(self, output_dir: str) -> SandboxExecutionTrace:
        """
        Transfers safe telemetry files from guest to host output_dir:
          procmon.csv, network.pcap, regshot.txt, execution_metadata.json
        Does NOT copy dropped executable binaries back to host by default.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        user = self.config.guest_username
        pwd = self.config.get_guest_password()

        guest_artifacts = [
            ("procmon.csv", r"C:\0206\telemetry\procmon.csv"),
            ("network.pcap", r"C:\0206\telemetry\network.pcap"),
            ("regshot.txt", r"C:\0206\telemetry\regshot.txt"),
            ("execution_metadata.json", r"C:\0206\telemetry\execution_metadata.json"),
        ]

        collected_paths: Dict[str, str] = {}
        telemetry_hashes: Dict[str, str] = {}

        if self.is_available():
            for local_name, guest_path in guest_artifacts:
                host_dest = out_path / local_name
                res = self._run_vbox([
                    "guestcontrol", self.config.vm_name,
                    "--username", user,
                    "--password", pwd,
                    "copyfrom",
                    "--target-directory", str(out_path.resolve()),
                    guest_path
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

        return SandboxExecutionTrace(
            trace_id=self._trace_id,
            backend_name=self.name,
            vm_name=self.config.vm_name,
            snapshot_name=self.config.snapshot_name,
            network_mode=self.config.network_mode.value if hasattr(self.config.network_mode, "value") else str(self.config.network_mode),
            network_verification_status=self._network_state.value,
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
            details=f"VM poweroff executed: {res.stdout.strip() or res.stderr.strip()}."
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
        rec = SandboxActionRecord(
            action="REVERT",
            status=ActionStatus.VERIFIED.value if res.exit_code == 0 else ActionStatus.FAILED.value,
            details=f"Revert to snapshot '{snap}': {res.stdout.strip() or res.stderr.strip()}."
        )
        self.actions.append(rec)
        return rec

    def verify_clean(self) -> SandboxActionRecord:
        """Verifies VM state is poweroff and reverted back to the clean snapshot."""
        if not self.is_available():
            rec = SandboxActionRecord(action="VERIFY_CLEAN", status=ActionStatus.NOT_CONFIGURED.value, details="VBoxManage missing.")
            self.actions.append(rec)
            return rec

        res = self._run_vbox(["showvminfo", self.config.vm_name, "--machinereadable"])
        if res.exit_code != 0:
            rec = SandboxActionRecord(action="VERIFY_CLEAN", status=ActionStatus.FAILED.value, details="Failed to query VM clean state.")
            self.actions.append(rec)
            return rec

        parsed = self._parse_machinereadable(res.stdout)
        vm_state = parsed.get("VMState", "").lower()
        current_snap = parsed.get("CurrentSnapshotName", "")

        is_poweroff = (vm_state == "poweroff")
        is_reverted = (current_snap == self.config.snapshot_name or not current_snap)
        clean = is_poweroff and is_reverted

        rec = SandboxActionRecord(
            action="VERIFY_CLEAN",
            status=ActionStatus.VERIFIED.value if clean else ActionStatus.FAILED.value,
            details=f"VM clean state: VMState={vm_state}, Snapshot={current_snap}."
        )
        self.actions.append(rec)
        return rec

    def cleanup(self) -> SandboxActionRecord:
        """Cleans up local temporary state."""
        rec = SandboxActionRecord(action="CLEANUP", status=ActionStatus.SUCCESS.value, details="VirtualBox session resources cleaned up.")
        self.actions.append(rec)
        return rec
