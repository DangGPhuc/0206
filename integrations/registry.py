"""
0206 - Tool Adapter Registry & Capability Detection
Implements a 3-tier capability architecture:
Tier 1: Zero external tools (pefile, scapy, capstone, docx)
Tier 2: Open-source optional tools (yara, ghidra, radare2, capa, pe-sieve)
Tier 3: Proprietary optional tools (IDA Pro, x64dbg, WinDbg)
Allows 0206 doctor to assess environment health without crashing.
"""
import sys
import shutil
import platform
import importlib.util
from typing import Dict, Any
from config import EXTERNAL_TOOLS


def check_python_package(package_name: str) -> Dict[str, Any]:
    """Checks if a python package is installed and returns version if possible."""
    spec = importlib.util.find_spec(package_name)
    if spec is None:
        return {"installed": False, "version": "unavailable"}

    version = "installed"
    try:
        mod = importlib.import_module(package_name)
        version = getattr(mod, "__version__", "installed")
    except Exception:
        pass

    return {"installed": True, "version": str(version)}


def check_executable(tool_name: str, config_override: str = "") -> Dict[str, Any]:
    """Checks if an external CLI tool is available on the system PATH or override path."""
    target = config_override or tool_name
    found_path = shutil.which(target)
    if found_path:
        return {"available": True, "path": found_path, "status": "AVAILABLE"}

    # Platform compatibility check
    current_os = platform.system()
    if tool_name in ("x64dbg", "windbg") and current_os != "Windows":
        return {"available": False, "path": None, "status": "NOT_AVAILABLE_ON_PLATFORM"}

    return {"available": False, "path": None, "status": "NOT_INSTALLED"}


class CapabilityRegistry:
    """Detects and reports available platform capabilities across the 3 tiers."""

    @staticmethod
    def get_capabilities() -> Dict[str, Any]:
        capabilities = {}

        # ---------------- Tier 1: Core / Built-in ----------------
        packages = {
            "pefile": "pefile",
            "scapy": "scapy",
            "capstone": "capstone",
            "python-docx": "docx",
            "pydantic": "pydantic",
            "rich": "rich"
        }
        for display_name, pkg in packages.items():
            info = check_python_package(pkg)
            capabilities[display_name] = {
                "tier": "Tier 1 (Core)",
                "status": "AVAILABLE" if info["installed"] else "MISSING",
                "version": info["version"],
                "installed": info["installed"],
                "capabilities": ["Core Triaging", "PE Parsing", "Disassembly", "Network Streaming"]
            }

        # ---------------- Tier 2 & 3: Adapters from ADAPTER_REGISTRY ----------------
        from integrations.adapters import ADAPTER_REGISTRY

        for name, adapter_cls in ADAPTER_REGISTRY.items():
            adapter = adapter_cls()
            status, reason = adapter.check_functional()
            status_val = status.value if hasattr(status, "value") else str(status)
            capabilities[name] = {
                "tier": adapter.tier,
                "status": status_val,
                "version": adapter.version,
                "capabilities": adapter.capabilities,
                "details": reason,
                "installed": adapter.available()
            }

        return capabilities

