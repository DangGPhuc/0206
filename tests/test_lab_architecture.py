"""
Tests for Phase 13, 14, 15: Windows REM Lab Workstation, Network Lab Verifier, and Snapshot Management.
"""
import pytest
from pathlib import Path
from lab.windows.detector import WindowsLabDetector, ToolAuditResult
from lab.windows.provisioner import WindowsLabProvisioner
from lab.network.verifier import NetworkLabVerifier, NetworkPolicyMode, NetworkLabAuditRecord
from lab.snapshots.manager import SnapshotManager, SnapshotStatus


def test_windows_lab_detector():
    """Auditing lab environment must return well-formed ToolAuditResults with valid status."""
    results = WindowsLabDetector.audit()
    assert len(results) > 0

    valid_statuses = {
        "NOT_INSTALLED", "DETECTED", "READY", "FUNCTIONAL",
        "PARTIAL", "FAILED", "NOT_SUPPORTED", "NOT_CONFIGURED"
    }

    for r in results:
        assert isinstance(r, ToolAuditResult)
        assert r.name
        assert r.category
        assert r.status in valid_statuses, f"Tool {r.name} status {r.status} not in valid 8 states"


def test_windows_lab_provisioner():
    """Provisioner must generate reproducible scripts with Chocolatey packages."""
    ps1 = WindowsLabProvisioner.generate_powershell_script()
    assert "# =====================================================================" in ps1
    assert "choco install" in ps1
    assert "sysinternals" in ps1
    assert "wireshark" in ps1

    choco_list = WindowsLabProvisioner.get_chocolatey_command()
    assert "choco install -y" in choco_list


def test_network_lab_verifier():
    """Network verification must return structured audit records with interface and status."""
    audit = NetworkLabVerifier.verify_network_policy(NetworkPolicyMode.ISOLATED)
    assert isinstance(audit, NetworkLabAuditRecord)
    assert audit.interface
    assert audit.policy_mode == NetworkPolicyMode.ISOLATED
    assert audit.dns_mode in ("STANDARD", "FAKEDNS", "INETSIM", "BLOCKED")
    assert audit.verification_status in ("VERIFIED_ISOLATED", "LEAK_DETECTED", "VERIFIED_SIMULATED", "UNVERIFIED")


def test_snapshot_manager():
    """Snapshot manager tracks baseline and restoration state without faking success."""
    mgr = SnapshotManager(provider_name="builtin_safe")
    baseline = mgr.create_baseline("test_vm", "clean_base")
    assert baseline.provider == "builtin_safe"
    assert baseline.status == SnapshotStatus.VERIFIED

    verified = mgr.verify_baseline(baseline.snapshot_id)
    assert verified is True

    restored = mgr.restore_baseline(baseline.snapshot_id)
    assert restored.status == SnapshotStatus.RESTORED

