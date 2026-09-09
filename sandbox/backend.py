"""
0206 - Sandbox Backend Abstract Interface
Phase 11: Standardized sandbox backend interface.
Every backend must implement prepare, snapshot, execute, monitor, collect, stop, revert, cleanup.
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from sandbox.schema import (
    SandboxGuestConfig,
    SandboxActionRecord,
    SandboxExecutionTrace,
    SandboxStatus,
)


class SandboxBackend(ABC):
    """Abstract interface for dynamic malware execution environments."""

    def __init__(self, config: Optional[SandboxGuestConfig] = None):
        self.config = config or SandboxGuestConfig()
        self.actions: List[SandboxActionRecord] = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend name (e.g. 'builtin', 'qemu', 'external')."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if hypervisor/backend environment is operational."""
        pass

    @abstractmethod
    def prepare(self) -> SandboxActionRecord:
        """Prepare VM environment or verify base requirements."""
        pass

    @abstractmethod
    def verify_baseline(self) -> SandboxActionRecord:
        """Verify baseline snapshot exists and guest system is clean."""
        pass

    @abstractmethod
    def snapshot(self, snapshot_name: Optional[str] = None) -> SandboxActionRecord:
        """Take or verify a baseline snapshot before detonation."""
        pass

    @abstractmethod
    def start(self) -> SandboxActionRecord:
        """Power on or resume the guest VM from clean snapshot."""
        pass

    @abstractmethod
    def transfer(self, sample_path: str, target_guest_path: Optional[str] = None) -> SandboxActionRecord:
        """Safely transfer sample binary into the isolated guest environment."""
        pass

    @abstractmethod
    def execute(self, sample_path: str, arguments: Optional[List[str]] = None) -> SandboxActionRecord:
        """Execute the sample inside the isolated guest."""
        pass

    @abstractmethod
    def monitor(self, duration_seconds: Optional[int] = None) -> SandboxActionRecord:
        """Monitor guest telemetry (processes, network, registry, filesystem)."""
        pass

    @abstractmethod
    def collect(self, output_dir: str) -> SandboxExecutionTrace:
        """Collect execution artifacts (PCAP, Procmon CSV, dropped files)."""
        pass

    @abstractmethod
    def stop(self) -> SandboxActionRecord:
        """Halt the guest VM / terminate guest processes."""
        pass

    @abstractmethod
    def revert(self, snapshot_name: Optional[str] = None) -> SandboxActionRecord:
        """Revert the guest VM back to the clean baseline state."""
        pass

    @abstractmethod
    def verify_clean(self) -> SandboxActionRecord:
        """Verify guest has successfully reverted to the uninfected baseline state."""
        pass

    @abstractmethod
    def cleanup(self) -> SandboxActionRecord:
        """Clean up any temporary files or sockets on the host."""
        pass
