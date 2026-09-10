"""
0206 - Sandbox Controller
Phase 11: Orchestrates dynamic analysis environments while strictly preventing unsafe local malware execution.
Enforces fail-closed gating:
  PREPARE -> VERIFY_VM -> VERIFY_BASELINE -> RESTORE_BASELINE -> VERIFY_NETWORK ->
  START -> VERIFY_GUEST_CONTROL -> START_TELEMETRY -> TRANSFER -> EXECUTE
Followed by guaranteed cleanup in try/finally:
  stop_telemetry -> collect -> stop -> revert -> verify_clean -> cleanup
"""
import logging
import tempfile
from typing import Dict, Optional, List, Any, Union
from datetime import datetime, timezone

from sandbox.backend import SandboxBackend
from sandbox.schema import (
    SandboxGuestConfig,
    SandboxExecutionTrace,
    SandboxStatus,
    ActionStatus,
    SandboxActionRecord,
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
    Enforces fail-closed pre-execution gates and guaranteed cleanup.
    """

    def __init__(
        self,
        config: Optional[SandboxGuestConfig] = None,
        backend_type: str = "builtin",
        backend_instance: Optional[SandboxBackend] = None,
    ):
        self.config = config or SandboxGuestConfig()
        if backend_instance is not None:
            self.backends = {backend_instance.name: backend_instance}
            self.selected_backend = backend_instance
            return

        self.backends: Dict[str, SandboxBackend] = {
            "builtin": BuiltinSandboxBackend(self.config),
            "builtin_safe": BuiltinSandboxBackend(self.config),
            "qemu": QemuSandboxBackend(self.config),
            "vmware": VMwareSandboxBackend(self.config),
            "virtualbox": VirtualBoxSandboxBackend(self.config),
            "external": ExternalSandboxBackend(self.config),
        }
        if backend_type not in self.backends:
            raise ValueError(
                f"Unknown requested sandbox backend '{backend_type}'. "
                f"Valid backends are: {sorted(list(self.backends.keys()))}."
            )
        self.selected_backend: SandboxBackend = self.backends[backend_type]

    def set_backend(self, backend_name: str) -> bool:
        if backend_name in self.backends:
            self.selected_backend = self.backends[backend_name]
            return True
        raise ValueError(
            f"Unknown requested sandbox backend '{backend_name}'. "
            f"Valid backends are: {sorted(list(self.backends.keys()))}."
        )

    def is_backend_available(self, backend_name: Optional[str] = None) -> bool:
        b = self.backends.get(backend_name) if backend_name else self.selected_backend
        return b.is_available() if b else False

    def detonate(self, sample_path: Any, output_dir: Optional[Any] = None) -> SandboxExecutionTrace:
        """Convenience alias for run_safe_session."""
        s_path = str(sample_path)
        if output_dir:
            return self.run_safe_session(s_path, str(output_dir))
        with tempfile.TemporaryDirectory() as td:
            return self.run_safe_session(s_path, td)

    def run_safe_session(self, sample_path: str, output_dir: str) -> SandboxExecutionTrace:
        """
        Executes a fail-closed dynamic analysis session with mandatory pre-execution gates:
          PREPARE -> VERIFY_VM -> VERIFY_BASELINE -> RESTORE_BASELINE -> VERIFY_NETWORK ->
          START -> VERIFY_GUEST_CONTROL -> START_TELEMETRY -> TRANSFER -> EXECUTE -> MONITOR
        Guaranteed post-execution cleanup in try/finally:
          stop_telemetry -> collect -> stop -> revert -> verify_clean -> cleanup
        """
        backend = self.selected_backend
        logger.info(f"Initiating fail-closed sandbox session with backend: {backend.name}")

        gates = [
            ("PREPARE", backend.prepare),
            ("VERIFY_VM", backend.verify_vm),
            ("VERIFY_BASELINE", backend.verify_baseline),
            ("RESTORE_BASELINE", backend.restore_baseline),
            ("VERIFY_NETWORK", backend.verify_network),
            ("START", backend.start),
            ("VERIFY_GUEST_CONTROL", backend.verify_guest_control),
            ("START_TELEMETRY", backend.start_telemetry),
            ("TRANSFER", lambda: backend.transfer(sample_path)),
        ]

        trace: Optional[SandboxExecutionTrace] = None
        executed = False
        execution_errors: List[str] = []
        execution_warnings: List[str] = []
        gate_failed = False
        revert_ok = False

        try:
            # 1. Mandatory sequential pre-execution gates
            for gate_name, gate_fn in gates:
                logger.info(f"Checking sandbox mandatory gate: {gate_name}...")
                rec: SandboxActionRecord = gate_fn()
                if not rec.is_success():
                    gate_failed = True
                    err_msg = f"Mandatory sandbox gate '{gate_name}' failed with status '{rec.status}': {rec.details}"
                    logger.error(err_msg)
                    execution_errors.append(err_msg)
                    break

            if not gate_failed:
                # 2. Advance to EXECUTE ONLY if all mandatory gates succeeded
                logger.info("All pre-execution gates verified successfully. Authorizing live EXECUTE...")
                exec_rec = backend.execute(sample_path)
                if not exec_rec.is_success():
                    err_msg = f"In-guest EXECUTE failed with status '{exec_rec.status}': {exec_rec.details}"
                    logger.error(err_msg)
                    execution_errors.append(err_msg)
                else:
                    executed = True

                # 3. Monitor bounded execution window
                logger.info("Monitoring in-guest execution window...")
                backend.monitor()

        except Exception as ex:
            logger.error(f"Sandbox execution error on backend {backend.name}: {ex}", exc_info=True)
            execution_errors.append(str(ex))

        finally:
            # Guaranteed post-execution cleanup: always attempted
            logger.info("Initiating guaranteed post-execution sandbox cleanup...")
            try:
                backend.stop_telemetry()
            except Exception as ex:
                execution_warnings.append(f"stop_telemetry error: {ex}")

            try:
                trace = backend.collect(output_dir)
            except Exception as ex:
                execution_errors.append(f"telemetry collection error: {ex}")

            try:
                backend.stop()
            except Exception as ex:
                execution_warnings.append(f"VM stop error: {ex}")

            revert_rec: Optional[SandboxActionRecord] = None
            try:
                revert_rec = backend.revert()
            except Exception as ex:
                execution_errors.append(f"VM revert error: {ex}")

            verify_clean_rec: Optional[SandboxActionRecord] = None
            try:
                verify_clean_rec = backend.verify_clean()
            except Exception as ex:
                execution_errors.append(f"VM clean verification error: {ex}")

            try:
                backend.cleanup()
            except Exception as ex:
                execution_warnings.append(f"cleanup error: {ex}")

            # Revert verification check
            revert_ok = bool(
                revert_rec is not None and revert_rec.is_success() and
                verify_clean_rec is not None and verify_clean_rec.is_success()
            )
            if not revert_ok:
                err_msg = "Baseline restoration unverified: VM may be in contaminated state."
                logger.error(err_msg)
                execution_errors.append(err_msg)

        # Build / finalize trace
        if trace is None:
            trace = SandboxExecutionTrace(
                trace_id=getattr(backend, "_trace_id", "session_trace"),
                backend_name=backend.name,
                vm_name=getattr(backend.config, "vm_name", ""),
                snapshot_name=getattr(backend.config, "snapshot_name", ""),
                network_mode=str(getattr(backend.config, "network_mode", "ISOLATED")),
                actions=list(backend.actions),
            )

        trace.errors.extend(execution_errors)
        trace.warnings.extend(execution_warnings)

        if not revert_ok:
            trace.revert_status = "FAILED"
            trace.status = SandboxStatus.PARTIAL if executed else SandboxStatus.FAILED
        elif gate_failed or execution_errors:
            trace.status = SandboxStatus.FAILED
            trace.revert_status = "VERIFIED" if revert_ok else "FAILED"
        elif executed:
            trace.status = SandboxStatus.COMPLETED
            if not trace.execution_status or trace.execution_status in ("NOT_EXECUTED", "UNKNOWN"):
                trace.execution_status = "EXECUTED"
            trace.revert_status = "VERIFIED"
        else:
            trace.status = SandboxStatus.NOT_EXECUTED

        return trace
