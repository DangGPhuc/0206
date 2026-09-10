"""
0206 - Sandbox Architecture Data Schemas
Defines guest configurations, action records, execution trace schemas,
network verification states, and fail-closed lifecycle actions.
"""
import os
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict


class SandboxNetworkMode(str, Enum):
    ISOLATED = "ISOLATED"
    HOST_ONLY = "HOST_ONLY"
    SIMULATED_INTERNET = "SIMULATED_INTERNET"
    ALLOW_INTERNET = "ALLOW_INTERNET"


class SandboxNetworkState(str, Enum):
    """Verified sandbox network safety states (default-deny)."""
    VERIFIED_ISOLATED = "VERIFIED_ISOLATED"
    VERIFIED_HOST_ONLY = "VERIFIED_HOST_ONLY"
    VERIFIED_SIMULATED = "VERIFIED_SIMULATED"
    UNVERIFIED = "UNVERIFIED"
    LEAK_DETECTED = "LEAK_DETECTED"

    def is_verified_safe(self) -> bool:
        return self in (
            SandboxNetworkState.VERIFIED_ISOLATED,
            SandboxNetworkState.VERIFIED_HOST_ONLY,
            SandboxNetworkState.VERIFIED_SIMULATED,
        )


class ActionStatus(str, Enum):
    """Audited statuses for sandbox lifecycle actions."""
    SUCCESS = "SUCCESS"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    SCAFFOLD = "SCAFFOLD"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    SKIPPED = "SKIPPED"
    PARTIAL = "PARTIAL"
    SAFE_DRY_RUN = "SAFE_DRY_RUN"


class ExecutionSubStatus(str, Enum):
    """Fine-grained execution status semantics for in-guest detonation."""
    START_FAILED = "START_FAILED"
    STARTED = "STARTED"
    EXITED = "EXITED"
    TIMED_OUT = "TIMED_OUT"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class SandboxStatus(str, Enum):
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
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
    backend: str = "virtualbox"
    vm_name: str = "win10-malware-analysis"
    os_type: str = "Windows 10 x64"
    snapshot_name: str = "clean_triage_base"
    guest_username: str = "analyst"
    guest_password_env: str = "SANDBOX_GUEST_PASSWORD"
    guest_work_dir: str = r"C:\0206\work"
    guest_telemetry_dir: str = r"C:\0206\telemetry"
    execution_timeout_seconds: int = 120
    network_mode: SandboxNetworkMode = SandboxNetworkMode.ISOLATED
    agent_port: int = 8000
    enable_monitoring: bool = True
    enable_pcap: bool = True
    enable_procmon: bool = True
    enable_regshot: bool = True
    require_procmon: bool = True
    require_pcap: bool = True
    require_regshot: bool = False
    vbox_user_home: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)

    @property
    def execution_timeout(self) -> int:
        return self.execution_timeout_seconds

    def get_guest_password(self) -> str:
        """Resolves guest credentials securely from environment, avoiding disk/log serialization."""
        return os.getenv(self.guest_password_env, "")

    @classmethod
    def load_config(cls, config_path: Optional[str] = None) -> "SandboxGuestConfig":
        """
        Loads configuration from TOML file:
        1. Explicit config_path if provided
        2. ~/.config/0206/config.toml
        3. ./0206.toml
        Falls back to default config if no config file exists.
        """
        from pathlib import Path
        target: Optional[Path] = None
        if config_path:
            p = Path(config_path)
            if p.is_file():
                target = p
        else:
            candidates = [
                Path.home() / ".config" / "0206" / "config.toml",
                Path("0206.toml"),
                Path.home() / ".config" / "0206.toml",
            ]
            for c in candidates:
                if c.is_file():
                    target = c
                    break

        if not target:
            return cls()

        data: Dict[str, Any] = {}
        try:
            try:
                import tomllib
                with open(target, "rb") as f:
                    data = tomllib.load(f)
            except ImportError:
                import tomli
                with open(target, "rb") as f:
                    data = tomli.load(f)
        except Exception:
            # Fallback simple line-by-line parser for standard key = "value"
            try:
                with open(target, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or line.startswith("["):
                            continue
                        if "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip('"').strip("'")
                            data[k] = v
            except Exception:
                return cls()

        sandbox_dict = data.get("sandbox", data)
        # Parse fields safely
        kwargs: Dict[str, Any] = {}
        valid_keys = set(cls.model_fields.keys())
        for k, v in sandbox_dict.items():
            k_clean = k.replace("-", "_")
            if k_clean in ("execution_timeout", "timeout"):
                k_clean = "execution_timeout_seconds"
            if k_clean in valid_keys:
                if k_clean == "execution_timeout_seconds":
                    try:
                        kwargs[k_clean] = int(v)
                    except (ValueError, TypeError):
                        pass
                elif k_clean in ("enable_pcap", "enable_procmon", "enable_regshot", "require_procmon", "require_pcap", "require_regshot", "enable_monitoring"):
                    if isinstance(v, str):
                        kwargs[k_clean] = v.lower() in ("true", "1", "yes")
                    else:
                        kwargs[k_clean] = bool(v)
                elif k_clean == "network_mode":
                    try:
                        kwargs[k_clean] = SandboxNetworkMode(str(v).upper())
                    except ValueError:
                        pass
                else:
                    kwargs[k_clean] = str(v)

        return cls(**kwargs)


class SandboxLifecycleAction(str, Enum):
    """The canonical dynamic sandbox lifecycle actions."""
    PREPARE = "PREPARE"
    VERIFY_VM = "VERIFY_VM"
    VERIFY_BASELINE = "VERIFY_BASELINE"
    RESTORE_BASELINE = "RESTORE_BASELINE"
    VERIFY_NETWORK = "VERIFY_NETWORK"
    START = "START"
    VERIFY_GUEST_CONTROL = "VERIFY_GUEST_CONTROL"
    START_TELEMETRY = "START_TELEMETRY"
    TRANSFER = "TRANSFER"
    EXECUTE = "EXECUTE"
    MONITOR = "MONITOR"
    STOP_TELEMETRY = "STOP_TELEMETRY"
    COLLECT = "COLLECT"
    STOP = "STOP"
    REVERT = "REVERT"
    VERIFY_CLEAN = "VERIFY_CLEAN"
    CLEANUP = "CLEANUP"
    # Backward-compatible alias
    SNAPSHOT = "SNAPSHOT"


class SandboxActionRecord(BaseModel):
    """Audit record for individual sandbox lifecycle actions."""
    action: str
    status: str  # SUCCESS, VERIFIED, FAILED, SKIPPED, NOT_CONFIGURED, NOT_IMPLEMENTED, SCAFFOLD, etc.
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_ms: float = 0.0
    details: str = ""
    errors: List[str] = Field(default_factory=list)

    def is_success(self) -> bool:
        """Centralized typed check for verified successful status."""
        st = self.status.value if hasattr(self.status, "value") else str(self.status)
        return st.upper() in (ActionStatus.SUCCESS.value, ActionStatus.VERIFIED.value)


class SandboxExecutionTrace(BaseModel):
    """Complete captured telemetry and provenance from a sandbox dynamic run."""
    trace_id: str
    backend_name: str
    vm_name: str = ""
    snapshot_name: str = ""
    baseline_snapshot_uuid: Optional[str] = None
    network_mode: str = "ISOLATED"
    sandbox_network_mode: Optional[str] = None
    network_verification_status: str = "UNVERIFIED"
    sandbox_network_verification_status: Optional[str] = None
    status: SandboxStatus = SandboxStatus.COMPLETED
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    execution_duration: float = 0.0
    sample_guest_path: Optional[str] = None
    sample_sha256: Optional[str] = None
    actions: List[SandboxActionRecord] = Field(default_factory=list)
    pcap_path: Optional[str] = None
    procmon_csv_path: Optional[str] = None
    regshot_path: Optional[str] = None
    execution_metadata_path: Optional[str] = None
    processes_spawned: List[Dict[str, Any]] = Field(default_factory=list)
    dropped_file_metadata: List[Dict[str, Any]] = Field(default_factory=list)
    dropped_files: List[str] = Field(default_factory=list)
    telemetry_hashes: Dict[str, str] = Field(default_factory=dict)
    execution_status: str = "NOT_EXECUTED"
    revert_status: str = "PENDING"
    cleanup_status: str = "PENDING"
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    model_config = ConfigDict(use_enum_values=True)
