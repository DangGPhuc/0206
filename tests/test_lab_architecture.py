"""
Tests for Phase 13, 14, 15: Windows REM Lab Workstation, Network Lab Verifier, and Snapshot Management.
"""
import io
import os
import socket
from unittest.mock import patch
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


def test_network_verifier_localhost_dns_stub_not_simulated():
    """Localhost DNS stub (127.0.0.1 / 127.0.0.53) does not imply simulated DNS."""
    resolv_data = "nameserver 127.0.0.53\nnameserver 127.0.0.1\n"
    orig_open = open
    orig_exists = os.path.exists

    def custom_open(file, *args, **kwargs):
        if str(file) == "/etc/resolv.conf":
            return io.StringIO(resolv_data)
        return orig_open(file, *args, **kwargs)

    with patch("builtins.open", side_effect=custom_open), \
         patch("os.path.exists", side_effect=lambda p: True if p == "/etc/resolv.conf" else orig_exists(p)):
        audit = NetworkLabVerifier.verify_network_policy(NetworkPolicyMode.ISOLATED)
        assert "127.0.0.53" in audit.dns_servers
        assert "127.0.0.1" in audit.dns_servers
        assert audit.dns_mode == "STANDARD"
        assert audit.dns_mode != "LOCAL_SIMULATED"


def test_network_verifier_isolated_leak_detection():
    """ISOLATED or HOST_ONLY lab policy with reachable external egress must report LEAK_DETECTED."""
    with patch.object(socket.socket, "connect_ex", return_value=0):
        audit_isolated = NetworkLabVerifier.verify_network_policy(NetworkPolicyMode.ISOLATED)
        assert audit_isolated.egress_verified is True
        assert audit_isolated.verification_status == "LEAK_DETECTED"
        assert "LEAK DETECTED" in audit_isolated.details

        audit_host = NetworkLabVerifier.verify_network_policy(NetworkPolicyMode.HOST_ONLY)
        assert audit_host.egress_verified is True
        assert audit_host.verification_status == "LEAK_DETECTED"
        assert "LEAK DETECTED" in audit_host.details

    with patch.object(socket.socket, "connect_ex", return_value=111):
        audit_blocked = NetworkLabVerifier.verify_network_policy(NetworkPolicyMode.ISOLATED)
        assert audit_blocked.egress_verified is False
        assert audit_blocked.verification_status == "VERIFIED_ISOLATED"


def test_network_verifier_canonical_dns_modes():
    """DNS mode must stay within canonical supported values (STANDARD, FAKEDNS, INETSIM, BLOCKED)."""
    canonical_modes = {"STANDARD", "FAKEDNS", "INETSIM", "BLOCKED"}

    # Default without verified simulated services
    audit_default = NetworkLabVerifier.verify_network_policy()
    assert audit_default.dns_mode == "STANDARD"
    assert audit_default.dns_mode in canonical_modes

    # Explicit FakeDNS service
    audit_fake = NetworkLabVerifier.verify_network_policy(simulated_services=["FakeDNS"])
    assert audit_fake.dns_mode == "FAKEDNS"
    assert audit_fake.dns_mode in canonical_modes

    # Explicit INetSim service
    audit_inet = NetworkLabVerifier.verify_network_policy(simulated_services=["inetsim"])
    assert audit_inet.dns_mode == "INETSIM"
    assert audit_inet.dns_mode in canonical_modes

    # Explicit DNS blocking
    audit_block = NetworkLabVerifier.verify_network_policy(simulated_services=["dns_blocked"])
    assert audit_block.dns_mode == "BLOCKED"
    assert audit_block.dns_mode in canonical_modes


def test_network_verifier_unverified_firewall():
    """Unverified firewall is not falsely reported as configured and interface does not overclaim."""
    audit = NetworkLabVerifier.verify_network_policy(NetworkPolicyMode.ISOLATED)
    assert audit.firewall_state == "UNVERIFIED"
    assert audit.firewall_state != "CONFIGURED"
    if audit.ip_address and not audit.ip_address.startswith("127."):
        assert audit.interface != "lo"
