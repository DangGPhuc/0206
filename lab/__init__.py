"""
0206 - Analysis Lab Platform Layer
Encapsulates lab infrastructure, Windows REM workstation provisioning,
network policy verification, and hypervisor snapshot management.
External tools are evidence providers.
"""
from lab.windows.detector import WindowsLabDetector
from lab.network.verifier import NetworkLabVerifier, NetworkPolicyMode
from lab.snapshots.manager import SnapshotManager, SnapshotRecord, SnapshotStatus

__all__ = [
    "WindowsLabDetector",
    "NetworkLabVerifier",
    "NetworkPolicyMode",
    "SnapshotManager",
    "SnapshotRecord",
    "SnapshotStatus",
]
