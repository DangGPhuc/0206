"""
0206 - Sandbox Controller
Phase 11: Orchestrates dynamic analysis environments while strictly preventing unsafe local malware execution.
"""
import logging
from typing import Dict, Optional, Type
from sandbox.backend import SandboxBackend
from sandbox.schema import (
    SandboxGuestConfig,
    SandboxExecutionTrace,
    SandboxStatus,
)
from sandbox.backends.builtin import BuiltinSandboxBackend
from sandbox.backends.qemu import QemuSandboxBackend
from sandbox.backends.vmware import VMwareSandboxBackend
from sandbox.backends.virtualbox import VirtualBoxSandboxBackend
from sandbox.backends.external import ExternalSandboxBackend

logger = logging.getLogger("0206.sandbox.controller")


class SandboxController:
    """
    Central controller for dynamic execution backends.
    Guarantees that untrusted binaries are never executed directly on the host machine.
    """

    def __init__(self, config: Optional[SandboxGuestConfig] = None, backend_type: str = "builtin"):
        self.config = config or SandboxGuestConfig()
        self.backends: Dict[str, SandboxBackend] = {
            "builtin": BuiltinSandboxBackend(self.config),
            "builtin_safe": BuiltinSandboxBackend(self.config),
            "qemu": QemuSandboxBackend(self.config),
            "vmware": VMwareSandboxBackend(self.config),
            "virtualbox": VirtualBoxSandboxBackend(self.config),
            "external": ExternalSandboxBackend(self.config),
        }
        self.selected_backend: SandboxBackend = self.backends.get(backend_type, self.backends["builtin"])

    def set_backend(self, backend_name: str) -> bool:
        if backend_name in self.backends:
            self.selected_backend = self.backends[backend_name]
            return True
        logger.warning(f"Unknown sandbox backend '{backend_name}'. Defaulting to builtin safe backend.")
        return False

    def is_backend_available(self, backend_name: Optional[str] = None) -> bool:
        b = self.backends.get(backend_name) if backend_name else self.selected_backend
        return b.is_available() if b else False

    def run_safe_session(self, sample_path: str, output_dir: str) -> SandboxExecutionTrace:
        """
        Executes a controlled dynamic analysis session 12-stage lifecycle:
        prepare -> verify_baseline -> snapshot -> start -> transfer -> execute -> monitor -> collect -> stop -> revert -> verify_clean -> cleanup
        """
        backend = self.selected_backend
        logger.info(f"Initiating sandbox session with backend: {backend.name}")

        try:
            backend.prepare()
            backend.verify_baseline()
            backend.snapshot()
            backend.start()
            backend.transfer(sample_path)
            backend.execute(sample_path)
            backend.monitor()
            trace = backend.collect(output_dir)
            backend.stop()
            backend.revert()
            backend.verify_clean()
            backend.cleanup()
            return trace
        except Exception as ex:
            logger.error(f"Sandbox execution error on backend {backend.name}: {ex}", exc_info=True)
            try:
                backend.cleanup()
            except Exception:
                pass
            return SandboxExecutionTrace(
                trace_id="failed_session",
                backend_name=backend.name,
                status=SandboxStatus.FAILED,
                errors=[str(ex)],
            )
