"""
0206 - VMware Workstation / ESXi Sandbox Backend
Phase 12: Scaffolding for VMware vmrun automation.
Never reports SUCCESS for unconfigured or unimplemented VM operations.
"""
import shutil
import uuid
from typing import Optional, List
from datetime import datetime, timezone

from sandbox.backend import SandboxBackend
from sandbox.schema import (
    SandboxGuestConfig,
    SandboxActionRecord,
    SandboxExecutionTrace,
    SandboxStatus,
)


class VMwareSandboxBackend(SandboxBackend):
    """
    VMware hypervisor backend using vmrun CLI.
    """

    def __init__(self, config: Optional[SandboxGuestConfig] = None, vmrun_bin: Optional[str] = None):
        super().__init__(config)
        self.vmrun_bin = vmrun_bin or shutil.which("vmrun")
        self._trace_id = str(uuid.uuid4())

    @property
    def name(self) -> str:
        return "vmware"

    def is_available(self) -> bool:
        """Available only if vmrun binary is detected in PATH."""
        return self.vmrun_bin is not None

    def prepare(self) -> SandboxActionRecord:
        if not self.is_available():
            rec = SandboxActionRecord(action="PREPARE", status="NOT_CONFIGURED", details="VMware vmrun CLI not found in PATH.")
        else:
            rec = SandboxActionRecord(action="PREPARE", status="SCAFFOLD", details=f"VMware hypervisor {self.vmrun_bin} detected. VM automation is SCAFFOLD.")
        self.actions.append(rec)
        return rec

    def verify_baseline(self) -> SandboxActionRecord:
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="VERIFY_BASELINE", status=status, details="VMware baseline snapshot verification scaffolded.")
        self.actions.append(rec)
        return rec

    def snapshot(self, snapshot_name: Optional[str] = None) -> SandboxActionRecord:
        snap = snapshot_name or self.config.snapshot_name
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="SNAPSHOT", status=status, details=f"VMware snapshot check referenced ({snap}).")
        self.actions.append(rec)
        return rec

    def start(self) -> SandboxActionRecord:
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="START", status=status, details="VMware VM start scaffolded.")
        self.actions.append(rec)
        return rec

    def transfer(self, sample_path: str, target_guest_path: Optional[str] = None) -> SandboxActionRecord:
        status = "NOT_IMPLEMENTED" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="TRANSFER", status=status, details=f"Guest file transfer of {sample_path} via VMware Tools not implemented (scaffold).")
        self.actions.append(rec)
        return rec

    def execute(self, sample_path: str, arguments: Optional[List[str]] = None) -> SandboxActionRecord:
        status = "NOT_IMPLEMENTED" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="EXECUTE", status=status, details=f"VMware in-guest execution for {sample_path} not implemented (scaffold). Host execution disabled.")
        self.actions.append(rec)
        return rec

    def monitor(self, duration_seconds: Optional[int] = None) -> SandboxActionRecord:
        dur = duration_seconds or self.config.execution_timeout_seconds
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="MONITOR", status=status, details=f"VMware telemetry capture scaffolded ({dur}s).")
        self.actions.append(rec)
        return rec

    def collect(self, output_dir: str) -> SandboxExecutionTrace:
        return SandboxExecutionTrace(
            trace_id=self._trace_id,
            backend_name=self.name,
            status=SandboxStatus.SCAFFOLD if self.is_available() else SandboxStatus.NOT_CONFIGURED,
            finished_at=datetime.now(timezone.utc).isoformat(),
            actions=list(self.actions),
            dropped_files=[],
            processes_spawned=[],
            errors=[] if self.is_available() else ["VMware vmrun not found on this host."],
        )

    def stop(self) -> SandboxActionRecord:
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="STOP", status=status, details="VMware VM halt scaffolded.")
        self.actions.append(rec)
        return rec

    def revert(self, snapshot_name: Optional[str] = None) -> SandboxActionRecord:
        snap = snapshot_name or self.config.snapshot_name
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="REVERT", status=status, details=f"VMware snapshot revert scaffolded ({snap}).")
        self.actions.append(rec)
        return rec

    def verify_clean(self) -> SandboxActionRecord:
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="VERIFY_CLEAN", status=status, details="VMware guest clean state verification scaffolded.")
        self.actions.append(rec)
        return rec

    def cleanup(self) -> SandboxActionRecord:
        rec = SandboxActionRecord(action="CLEANUP", status="SCAFFOLD", details="VMware temporary handle cleanup scaffolded.")
        self.actions.append(rec)
        return rec
