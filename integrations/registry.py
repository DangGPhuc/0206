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
                "version": info["version"]
            }

        # ---------------- Tier 2: Open-source Optional ----------------
        yara_py = check_python_package("yara")
        yara_cli = check_executable("yara", EXTERNAL_TOOLS.get("yara", ""))
        yara_status = "AVAILABLE" if (yara_py["installed"] or yara_cli["available"]) else "NOT_INSTALLED"
        capabilities["YARA"] = {
            "tier": "Tier 2 (Open Source)",
            "status": yara_status,
            "version": yara_py["version"] if yara_py["installed"] else ("CLI" if yara_cli["available"] else "unavailable")
        }

        ghidra_info = check_executable("ghidra", EXTERNAL_TOOLS.get("ghidra", ""))
        capabilities["Ghidra"] = {
            "tier": "Tier 2 (Open Source)",
            "status": ghidra_info["status"],
            "path": ghidra_info["path"]
        }

        r2_info = check_executable("radare2")
        capabilities["radare2"] = {
            "tier": "Tier 2 (Open Source)",
            "status": r2_info["status"],
            "path": r2_info["path"]
        }

        capa_info = check_executable("capa")
        capabilities["capa"] = {
            "tier": "Tier 2 (Open Source)",
            "status": capa_info["status"],
            "path": capa_info["path"]
        }

        pesieve_info = check_executable("pe-sieve", EXTERNAL_TOOLS.get("pesieve", ""))
        capabilities["pe-sieve"] = {
            "tier": "Tier 2 (Open Source)",
            "status": pesieve_info["status"],
            "path": pesieve_info["path"]
        }

        floss_info = check_executable("floss")
        capabilities["FLOSS"] = {
            "tier": "Tier 2 (Open Source)",
            "status": floss_info["status"],
            "path": floss_info["path"]
        }

        # ---------------- Tier 3: Proprietary Optional ----------------
        ida_info = check_executable("ida64", EXTERNAL_TOOLS.get("ida", ""))
        if not ida_info["available"]:
            ida_info = check_executable("idat", EXTERNAL_TOOLS.get("ida", ""))
        capabilities["IDA Pro"] = {
            "tier": "Tier 3 (Proprietary)",
            "status": ida_info["status"],
            "path": ida_info["path"]
        }

        x64dbg_info = check_executable("x64dbg", EXTERNAL_TOOLS.get("x64dbg", ""))
        capabilities["x64dbg"] = {
            "tier": "Tier 3 (Proprietary)",
            "status": x64dbg_info["status"],
            "path": x64dbg_info["path"]
        }

        windbg_info = check_executable("windbg")
        capabilities["WinDbg"] = {
            "tier": "Tier 3 (Proprietary)",
            "status": windbg_info["status"],
            "path": windbg_info["path"]
        }

        return capabilities
