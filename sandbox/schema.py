"""
0206 - Sandbox Architecture Data Schemas
Defines guest configurations, action records, and execution trace schemas.
"""
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class SandboxNetworkMode(str, Enum):
    ISOLATED = "ISOLATED"
    HOST_ONLY = "HOST_ONLY"
    SIMULATED_INTERNET = "SIMULATED_INTERNET"
    ALLOW_INTERNET = "ALLOW_INTERNET"


class SandboxStatus(str, Enum):
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    SKIPPED = "SKIPPED"
    SIMULATED = "SIMULATED"
    NOT_EXECUTED = "NOT_EXECUTED"
    SAFE_DRY_RUN = "SAFE_DRY_RUN"
    SCAFFOLD = "SCAFFOLD"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    NOT_CONFIGURED = "NOT_CONFIGURED"


class SandboxGuestConfig(BaseModel):
    """Guest virtual machine / sandbox environment specifications."""
    vm_name: str = "win10-malware-analysis"
    os_type: str = "Windows 10 x64"
    snapshot_name: str = "clean_triage_base"
    network_mode: SandboxNetworkMode = SandboxNetworkMode.ISOLATED
    execution_timeout_seconds: int = 120
    agent_port: int = 8000
    enable_monitoring: bool = True
    enable_pcap: bool = True
    enable_procmon: bool = True

    class Config:
        use_enum_values = True


class SandboxLifecycleAction(str, Enum):
    """The 12 canonical dynamic sandbox lifecycle actions (Phase 11)."""
    PREPARE = "PREPARE"
    VERIFY_BASELINE = "VERIFY_BASELINE"
    SNAPSHOT = "SNAPSHOT"
    START = "START"
    TRANSFER = "TRANSFER"
    EXECUTE = "EXECUTE"
    MONITOR = "MONITOR"
    COLLECT = "COLLECT"
    STOP = "STOP"
    REVERT = "REVERT"
    VERIFY_CLEAN = "VERIFY_CLEAN"
    CLEANUP = "CLEANUP"


class SandboxActionRecord(BaseModel):
    """Audit record for individual sandbox lifecycle actions."""
    action: str
    status: str  # SUCCESS, FAILED, SKIPPED, NOT_CONFIGURED, NOT_IMPLEMENTED, SCAFFOLD
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_ms: float = 0.0
    details: str = ""
    errors: List[str] = Field(default_factory=list)


class SandboxExecutionTrace(BaseModel):
    """Complete captured telemetry from a sandbox dynamic run."""
    trace_id: str
    backend_name: str
    status: SandboxStatus = SandboxStatus.COMPLETED
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    actions: List[SandboxActionRecord] = Field(default_factory=list)
    pcap_path: Optional[str] = None
    procmon_csv_path: Optional[str] = None
    dropped_files: List[str] = Field(default_factory=list)
    processes_spawned: List[Dict[str, Any]] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True
