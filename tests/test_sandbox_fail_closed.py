"""
Fail-Closed SandboxController Unit Tests.
Verifies all mandatory pre-execution gates, fail-closed transitions,
guaranteed cleanup/revert in try/finally, and backend routing.
"""
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
import tempfile

from sandbox.schema import (
    SandboxGuestConfig,
    SandboxNetworkMode,
    SandboxNetworkState,
    SandboxStatus,
    ActionStatus,
    SandboxLifecycleAction,
    SandboxActionRecord,
    SandboxExecutionTrace,
)
from sandbox.controller import SandboxController
from sandbox.backend import SandboxBackend


class MockTestBackend(SandboxBackend):
    """Configurable mock sandbox backend for lifecycle gate testing."""
    def __init__(self, config=None, **kwargs):
        super().__init__(config or SandboxGuestConfig())
        self.available = kwargs.get("available", True)
        self.prepare_success = kwargs.get("prepare_success", True)
        self.vm_verified = kwargs.get("vm_verified", True)
        self.baseline_verified = kwargs.get("baseline_verified", True)
        self.restore_success = kwargs.get("restore_success", True)
        self.network_verified = kwargs.get("network_verified", True)
        self.network_state = kwargs.get("network_state", SandboxNetworkState.VERIFIED_HOST_ONLY)
        self.started = kwargs.get("started", True)
        self.guest_control_verified = kwargs.get("guest_control_verified", True)
        self.telemetry_started = kwargs.get("telemetry_started", True)
        self.transfer_success = kwargs.get("transfer_success", True)
        self.execute_success = kwargs.get("execute_success", True)
        self.execute_timeout = kwargs.get("execute_timeout", False)
        self.revert_success = kwargs.get("revert_success", True)
        self.clean_verified = kwargs.get("clean_verified", True)

        self.execute_called = False
        self.cleanup_called = False
        self.revert_called = False
        self.stop_called = False
        self.stop_telemetry_called = False
        self.collect_called = False

    @property
    def name(self) -> str:
        return "mock_test"

    def is_available(self) -> bool:
        return self.available

    def prepare(self) -> SandboxActionRecord:
        st = ActionStatus.SUCCESS.value if (self.available and self.prepare_success) else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="PREPARE", status=st)
        self.actions.append(rec)
        return rec

    def verify_vm(self) -> SandboxActionRecord:
        st = ActionStatus.VERIFIED.value if self.vm_verified else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="VERIFY_VM", status=st)
        self.actions.append(rec)
        return rec

    def verify_baseline(self) -> SandboxActionRecord:
        st = ActionStatus.VERIFIED.value if self.baseline_verified else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="VERIFY_BASELINE", status=st)
        self.actions.append(rec)
        return rec

    def restore_baseline(self, snapshot_name=None) -> SandboxActionRecord:
        st = ActionStatus.SUCCESS.value if self.restore_success else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="RESTORE_BASELINE", status=st)
        self.actions.append(rec)
        return rec

    def verify_network(self) -> SandboxActionRecord:
        st = ActionStatus.VERIFIED.value if self.network_verified else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="VERIFY_NETWORK", status=st, details=self.network_state.value)
        self.actions.append(rec)
        return rec

    def start(self) -> SandboxActionRecord:
        st = ActionStatus.SUCCESS.value if self.started else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="START", status=st)
        self.actions.append(rec)
        return rec

    def verify_guest_control(self) -> SandboxActionRecord:
        st = ActionStatus.VERIFIED.value if self.guest_control_verified else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="VERIFY_GUEST_CONTROL", status=st)
        self.actions.append(rec)
        return rec

    def start_telemetry(self) -> SandboxActionRecord:
        st = ActionStatus.SUCCESS.value if self.telemetry_started else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="START_TELEMETRY", status=st)
        self.actions.append(rec)
        return rec

    def transfer(self, sample_path: str, target_guest_path=None) -> SandboxActionRecord:
        st = ActionStatus.SUCCESS.value if self.transfer_success else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="TRANSFER", status=st)
        self.actions.append(rec)
        return rec

    def execute(self, sample_path: str, arguments=None) -> SandboxActionRecord:
        self.execute_called = True
        if self.execute_timeout:
            raise TimeoutError("Execution timed out")
        st = ActionStatus.SUCCESS.value if self.execute_success else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="EXECUTE", status=st)
        self.actions.append(rec)
        return rec

    def monitor(self, duration_seconds=None) -> SandboxActionRecord:
        rec = SandboxActionRecord(action="MONITOR", status=ActionStatus.SUCCESS.value)
        self.actions.append(rec)
        return rec

    def stop_telemetry(self) -> SandboxActionRecord:
        self.stop_telemetry_called = True
        rec = SandboxActionRecord(action="STOP_TELEMETRY", status=ActionStatus.SUCCESS.value)
        self.actions.append(rec)
        return rec

    def collect(self, output_dir: str) -> SandboxExecutionTrace:
        self.collect_called = True
        return SandboxExecutionTrace(
            trace_id="test_trace",
            backend_name="mock_test",
            network_mode=self.config.network_mode.value,
            network_verification_status=self.network_state.value,
            actions=self.actions,
        )

    def stop(self) -> SandboxActionRecord:
        self.stop_called = True
        rec = SandboxActionRecord(action="STOP", status=ActionStatus.SUCCESS.value)
        self.actions.append(rec)
        return rec

    def revert(self, snapshot_name=None) -> SandboxActionRecord:
        self.revert_called = True
        st = ActionStatus.SUCCESS.value if self.revert_success else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="REVERT", status=st)
        self.actions.append(rec)
        return rec

    def verify_clean(self) -> SandboxActionRecord:
        st = ActionStatus.VERIFIED.value if self.clean_verified else ActionStatus.FAILED.value
        rec = SandboxActionRecord(action="VERIFY_CLEAN", status=st)
        self.actions.append(rec)
        return rec

    def cleanup(self) -> SandboxActionRecord:
        self.cleanup_called = True
        rec = SandboxActionRecord(action="CLEANUP", status=ActionStatus.SUCCESS.value)
        self.actions.append(rec)
        return rec


class TestSandboxFailClosed(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.sample = Path(self.tmp_dir.name) / "sample.exe"
        self.sample.write_bytes(b"MZ\x90\x00FAKEPE")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_unknown_sandbox_backend_raises_error(self):
        """Requesting an unknown sandbox backend must raise an explicit ValueError and never silently fall back."""
        with self.assertRaises(ValueError) as ctx:
            SandboxController(backend_type="non_existent_hypervisor")
        self.assertIn("Unknown requested sandbox backend", str(ctx.exception))

    def test_backend_unavailable_blocks_execution(self):
        backend = MockTestBackend(available=False)
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertFalse(backend.execute_called)
        self.assertEqual(trace.status, SandboxStatus.FAILED)
        self.assertEqual(trace.execution_status, "NOT_EXECUTED")
        prep_action = next(a for a in trace.actions if a.action == SandboxLifecycleAction.PREPARE.value)
        self.assertEqual(prep_action.status, ActionStatus.FAILED.value)

    def test_vm_missing_blocks_execution(self):
        backend = MockTestBackend(vm_verified=False)
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertFalse(backend.execute_called)
        self.assertEqual(trace.status, SandboxStatus.FAILED)
        self.assertEqual(trace.execution_status, "NOT_EXECUTED")

    def test_baseline_snapshot_missing_blocks_execution(self):
        backend = MockTestBackend(baseline_verified=False)
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertFalse(backend.execute_called)
        self.assertEqual(trace.status, SandboxStatus.FAILED)
        self.assertEqual(trace.execution_status, "NOT_EXECUTED")

    def test_restore_baseline_failure_blocks_execution(self):
        backend = MockTestBackend(restore_success=False)
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertFalse(backend.execute_called)
        self.assertEqual(trace.status, SandboxStatus.FAILED)
        self.assertEqual(trace.execution_status, "NOT_EXECUTED")

    def test_network_leak_detected_blocks_execution(self):
        backend = MockTestBackend(
            network_verified=False,
            network_state=SandboxNetworkState.LEAK_DETECTED
        )
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertFalse(backend.execute_called)
        self.assertEqual(trace.status, SandboxStatus.FAILED)
        self.assertEqual(trace.network_verification_status, SandboxNetworkState.LEAK_DETECTED.value)
        self.assertEqual(trace.execution_status, "NOT_EXECUTED")

    def test_unverified_network_blocks_execution(self):
        backend = MockTestBackend(
            network_verified=False,
            network_state=SandboxNetworkState.UNVERIFIED
        )
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertFalse(backend.execute_called)
        self.assertEqual(trace.status, SandboxStatus.FAILED)

    def test_vm_start_failure_blocks_execution(self):
        backend = MockTestBackend(started=False)
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertFalse(backend.execute_called)
        self.assertEqual(trace.status, SandboxStatus.FAILED)

    def test_guest_control_unavailable_blocks_execution(self):
        backend = MockTestBackend(guest_control_verified=False)
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertFalse(backend.execute_called)
        self.assertEqual(trace.status, SandboxStatus.FAILED)

    def test_telemetry_start_failure_blocks_execution(self):
        backend = MockTestBackend(telemetry_started=False)
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertFalse(backend.execute_called)
        self.assertEqual(trace.status, SandboxStatus.FAILED)

    def test_transfer_failure_blocks_execution(self):
        backend = MockTestBackend(transfer_success=False)
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertFalse(backend.execute_called)
        self.assertEqual(trace.status, SandboxStatus.FAILED)

    def test_execution_timeout_guarantees_cleanup_and_revert(self):
        backend = MockTestBackend(execute_timeout=True)
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertTrue(backend.execute_called)
        self.assertTrue(backend.stop_telemetry_called)
        self.assertTrue(backend.collect_called)
        self.assertTrue(backend.stop_called)
        self.assertTrue(backend.revert_called)
        self.assertTrue(backend.cleanup_called)
        self.assertEqual(trace.status, SandboxStatus.FAILED)
        self.assertIn("Execution timed out", str(trace.errors))

    def test_revert_verification_failure_prevents_completed_status(self):
        # Even if execution succeeds, if revert verification fails, status must NEVER be COMPLETED
        backend = MockTestBackend(clean_verified=False)
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertTrue(backend.execute_called)
        self.assertTrue(backend.revert_called)
        self.assertNotEqual(trace.status, SandboxStatus.COMPLETED)
        self.assertIn(trace.status, (SandboxStatus.FAILED, SandboxStatus.PARTIAL))
        self.assertEqual(trace.revert_status, ActionStatus.FAILED.value)

    def test_successful_run_reaches_completed(self):
        backend = MockTestBackend()
        controller = SandboxController(backend_type="mock_test", backend_instance=backend)
        trace = controller.detonate(self.sample)
        self.assertTrue(backend.execute_called)
        self.assertEqual(trace.status, SandboxStatus.COMPLETED)
        self.assertEqual(trace.execution_status, "EXECUTED")
        self.assertEqual(trace.revert_status, ActionStatus.VERIFIED.value)


if __name__ == "__main__":
    unittest.main()
