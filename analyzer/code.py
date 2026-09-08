"""
0206 - Static Disassembly Module (Capstone Integration)
Performs static entry-point instruction analysis with graceful fallback.
Never crashes if Capstone is missing.
"""
from pathlib import Path
from typing import Dict, List, Any, Optional
import pefile

from core.evidence import EvidenceStore, EvidenceState

# Try importing Capstone safely
try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    capstone = None
    CAPSTONE_AVAILABLE = False


class CodeAnalyzer:
    """Analyzes entry-point instructions and suspicious control-flow patterns."""

    def __init__(self, file_path: Path, evidence_store: Optional[EvidenceStore] = None):
        self.file_path = Path(file_path)
        self.evidence_store = evidence_store if evidence_store is not None else EvidenceStore()

    def analyze(self, max_instructions: int = 30) -> Dict[str, Any]:
        """Disassembles the entry point of the binary."""
        artifact_name = self.file_path.name
        result: Dict[str, Any] = {
            "status": "NOT_ANALYZED",
            "architecture": "Unknown",
            "entry_point": "0x0",
            "instructions": [],
            "suspicious_patterns": [],
            "warnings": []
        }

        if not CAPSTONE_AVAILABLE:
            result["status"] = "NOT_AVAILABLE"
            result["warnings"].append("Capstone disassembly library is not installed (run: pip install capstone).")
            self.evidence_store.create(
                artifact_name, "DISASSEMBLY", "capstone_status", "NOT_AVAILABLE",
                "CodeAnalyzer", state=EvidenceState.NOT_AVAILABLE
            )
            return result

        if not self.file_path.exists():
            result["warnings"].append(f"Target file does not exist: {self.file_path}")
            return result

        try:
            pe = pefile.PE(str(self.file_path), fast_load=True)
            ep_rva = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)
            image_base = getattr(pe.OPTIONAL_HEADER, "ImageBase", 0)
            is_64bit = (pe.FILE_HEADER.Machine == 0x8664)

            result["entry_point"] = f"0x{ep_rva:08X}"
            result["architecture"] = "x64" if is_64bit else "x86"

            # Locate raw offset of entry point
            raw_offset = None
            for sec in pe.sections:
                if sec.VirtualAddress <= ep_rva < sec.VirtualAddress + sec.Misc_VirtualSize:
                    raw_offset = ep_rva - sec.VirtualAddress + sec.PointerToRawData
                    break

            if raw_offset is None:
                result["warnings"].append(f"Entry point RVA 0x{ep_rva:X} does not map to any raw PE section.")
                return result

            # Read entry point bytes
            with open(self.file_path, "rb") as f:
                f.seek(raw_offset)
                code_bytes = f.read(256)

            # Initialize Capstone engine
            md = capstone.Cs(
                capstone.CS_ARCH_X86,
                capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32
            )

            instructions = []
            suspicious = []
            va_start = image_base + ep_rva

            for insn in md.disasm(code_bytes, va_start):
                insn_str = f"0x{insn.address:08X}:  {insn.mnemonic:<8} {insn.op_str}"
                instructions.append(insn_str)

                # Heuristic patterns
                # 1. Direct Syscall
                if insn.mnemonic in ("syscall", "sysenter"):
                    pattern = f"Direct Syscall invocation at 0x{insn.address:08X}"
                    suspicious.append(pattern)
                    self.evidence_store.create(
                        artifact_name, "DISASSEMBLY", "direct_syscall", pattern,
                        "CodeAnalyzer", provenance={"address": f"0x{insn.address:X}"}
                    )

                # 2. PEB / TEB access
                if "gs:[0x60]" in insn.op_str.lower() or "gs:[60h]" in insn.op_str.lower():
                    pattern = f"Direct x64 PEB access via GS segment at 0x{insn.address:08X}"
                    suspicious.append(pattern)
                    self.evidence_store.create(
                        artifact_name, "DISASSEMBLY", "peb_access", pattern,
                        "CodeAnalyzer", provenance={"address": f"0x{insn.address:X}"}
                    )
                elif "fs:[0x30]" in insn.op_str.lower() or "fs:[30h]" in insn.op_str.lower():
                    pattern = f"Direct x86 PEB access via FS segment at 0x{insn.address:08X}"
                    suspicious.append(pattern)
                    self.evidence_store.create(
                        artifact_name, "DISASSEMBLY", "peb_access", pattern,
                        "CodeAnalyzer", provenance={"address": f"0x{insn.address:X}"}
                    )

                if len(instructions) >= max_instructions:
                    break

            result["status"] = "OBSERVED"
            result["instructions"] = instructions
            result["suspicious_patterns"] = suspicious

            self.evidence_store.create(
                artifact_name, "DISASSEMBLY", "entry_instructions", instructions[:10],
                "CodeAnalyzer", provenance={"instruction_count": len(instructions)}
            )

        except Exception as e:
            result["warnings"].append(f"Disassembly failed: {e}")

        return result
