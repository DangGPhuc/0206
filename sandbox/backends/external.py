"""
0206 - External Lab / REST Sandbox Backend
Phase 11: Scaffolding for external automated dynamic analysis clusters (CAPE/Cuckoo/Custom Lab).
"""
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


class ExternalSandboxBackend(SandboxBackend):
    """
    External dynamic analysis backend.
    Communicates with dedicated lab environments or external sandboxes over a secure API.
    """

    def __init__(self, config: Optional[SandboxGuestConfig] = None, api_endpoint: Optional[str] = None):
        super().__init__(config)
        self.api_endpoint = api_endpoint
        self._trace_id = str(uuid.uuid4())

    @property
    def name(self) -> str:
        return "external_api"

    def is_available(self) -> bool:
        """Available only if an external endpoint has been configured."""
        return bool(self.api_endpoint)

    def prepare(self) -> SandboxActionRecord:
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="PREPARE", status=status, details=f"External endpoint: {self.api_endpoint or 'NOT_CONFIGURED'}")
        self.actions.append(rec)
        return rec

    def snapshot(self, snapshot_name: Optional[str] = None) -> SandboxActionRecord:
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="SNAPSHOT", status=status, details="External backend remote VM snapshot management scaffolded.")
        self.actions.append(rec)
        return rec

    def execute(self, sample_path: str, arguments: Optional[List[str]] = None) -> SandboxActionRecord:
        if not self.is_available():
            rec = SandboxActionRecord(action="EXECUTE", status="NOT_CONFIGURED", details="No external sandbox endpoint configured.")
            self.actions.append(rec)
            return rec
        rec = SandboxActionRecord(action="EXECUTE", status="NOT_IMPLEMENTED", details=f"Dispatch to {self.api_endpoint} is currently scaffolded. Live submission blocked.")
        self.actions.append(rec)
        return rec

    def monitor(self, duration_seconds: Optional[int] = None) -> SandboxActionRecord:
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="MONITOR", status=status, details="Remote execution monitor scaffolded.")
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
            errors=[] if self.is_available() else ["External sandbox endpoint not configured."],
        )

    def stop(self) -> SandboxActionRecord:
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="STOP", status=status, details="Remote job termination scaffolded.")
        self.actions.append(rec)
        return rec

    def revert(self, snapshot_name: Optional[str] = None) -> SandboxActionRecord:
        status = "SCAFFOLD" if self.is_available() else "NOT_CONFIGURED"
        rec = SandboxActionRecord(action="REVERT", status=status, details="Remote snapshot restoration scaffolded.")
        self.actions.append(rec)
        return rec

    def cleanup(self) -> SandboxActionRecord:
        rec = SandboxActionRecord(action="CLEANUP", status="SCAFFOLD", details="External session resource cleanup scaffolded.")
        self.actions.append(rec)
        return rec
