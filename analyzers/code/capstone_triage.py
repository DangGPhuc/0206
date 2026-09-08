"""
0206 - Static Code Triage Analyzer (Capstone Disassembly Engine)
Independent core disassembly engine providing fast initial static code triage.
Extracts entry-point instructions, invalid instruction sequences, suspicious instruction
patterns (direct syscalls, PEB access), and control-flow branch hints.
Does not claim to replace interactive decompilers (IDA/Ghidra).
"""
import pefile
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from core.schemas import AnalysisDomain, EvidenceState
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming


class CodeAnalyzer:
    """
    Performs fast static code triage on PE entry points using Capstone.
    Emits atomic evidence items tagged by AnalysisDomain.ASSEMBLY.
    """

    def __init__(self, file_path: Path, evidence_store: Optional[EvidenceStore] = None, max_instructions: int = 150):
        self.file_path = Path(file_path)
        self.evidence_store = evidence_store or EvidenceStore()
        self.max_instructions = max_instructions
        self.errors: List[str] = []

    def analyze(self) -> Dict[str, Any]:
        """Runs entry-point disassembly and heuristic pattern detection."""
        if not self.file_path.exists():
            return {"status": "ERROR", "message": f"File not found: {self.file_path}"}

        hashes = hash_file_streaming(self.file_path)
        sha256 = hashes.get("sha256", "UNKNOWN")

        if not CAPSTONE_AVAILABLE:
            self.evidence_store.create(
                self.file_path.name, "DISASSEMBLY", "capstone_engine", "NOT_AVAILABLE",
                "CodeAnalyzer", state=EvidenceState.NOT_AVAILABLE, domain=AnalysisDomain.ASSEMBLY,
                artifact_sha256=sha256
            )
            return {
                "status": "NOT_AVAILABLE",
                "instructions": [],
                "disassembly_text": "Capstone disassembly engine not installed."
            }

        try:
            with open(self.file_path, "rb") as f:
                data = f.read()

            pe = pefile.PE(data=data, fast_load=True)
            arch_mode = CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else CS_MODE_32
            arch_str = "x64" if arch_mode == CS_MODE_64 else "x86"

            entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = pe.OPTIONAL_HEADER.ImageBase
            entry_va = image_base + entry_rva

            # Locate section containing entry point
            code_bytes = b""
            for sec in pe.sections:
                sec_vaddr = sec.VirtualAddress
                sec_vsize = sec.Misc_VirtualSize
                if sec_vaddr <= entry_rva < sec_vaddr + sec_vsize:
                    offset = sec.PointerToRawData + (entry_rva - sec_vaddr)
                    code_bytes = data[offset:offset + 4096]
                    break

            if not code_bytes:
                return {"status": "NOT_FOUND", "instructions": [], "disassembly_text": "Entry point section raw bytes not found."}

            md = Cs(CS_ARCH_X86, arch_mode)
            md.detail = True

            instructions = []
            suspicious_patterns = []
            invalid_count = 0
            call_targets = []

            for insn in md.disasm(code_bytes, entry_va):
                addr_hex = hex(insn.address)
                mnemonic = insn.mnemonic
                op_str = insn.op_str
                line_str = f"{addr_hex}: {mnemonic} {op_str}".strip()

                inst_dict = {
                    "address": addr_hex,
                    "mnemonic": mnemonic,
                    "op_str": op_str,
                    "bytes": insn.bytes.hex()
                }
                instructions.append(inst_dict)

                # Heuristic 1: Direct Syscall Detection (Evasion)
                if mnemonic in ("syscall", "sysenter") or (mnemonic == "int" and "0x2e" in op_str):
                    suspicious_patterns.append({
                        "pattern": "DIRECT_SYSCALL",
                        "address": addr_hex,
                        "instruction": line_str,
                        "description": "Direct kernel syscall invoked directly from binary code, bypassing ntdll hooks."
                    })
                    self.evidence_store.create(
                        self.file_path.name, "DISASSEMBLY", "direct_syscall", line_str, "CodeAnalyzer",
                        domain=AnalysisDomain.ANTI_ANALYSIS, artifact_sha256=sha256,
                        source_offset=addr_hex, provenance={"address": addr_hex, "pattern": "DIRECT_SYSCALL"}
                    )

                # Heuristic 2: Process Environment Block (PEB) Access
                if "fs:[0x30]" in op_str or "gs:[0x60]" in op_str or "fs:[0x18]" in op_str:
                    suspicious_patterns.append({
                        "pattern": "PEB_ACCESS",
                        "address": addr_hex,
                        "instruction": line_str,
                        "description": "Direct segment register access to the Process Environment Block (PEB) or TEB."
                    })
                    self.evidence_store.create(
                        self.file_path.name, "DISASSEMBLY", "peb_access", line_str, "CodeAnalyzer",
                        domain=AnalysisDomain.OBFUSCATION, artifact_sha256=sha256,
                        source_offset=addr_hex, provenance={"address": addr_hex, "pattern": "PEB_ACCESS"}
                    )

                # Heuristic 3: Call Instructions & Branch Targets
                if mnemonic == "call":
                    call_targets.append(op_str)

                if len(instructions) >= self.max_instructions:
                    break

            # Record entry point disassembly triage evidence
            self.evidence_store.create(
                self.file_path.name, "DISASSEMBLY", "entry_point_triage", {
                    "instruction_count": len(instructions),
                    "architecture": arch_str,
                    "entry_va": hex(entry_va),
                    "suspicious_patterns_count": len(suspicious_patterns)
                }, "CodeAnalyzer", domain=AnalysisDomain.ASSEMBLY, artifact_sha256=sha256
            )

            disasm_lines = [f"{i['address']}: {i['mnemonic']} {i['op_str']}" for i in instructions]

            return {
                "status": "COMPLETED",
                "architecture": arch_str,
                "entry_va": hex(entry_va),
                "instruction_count": len(instructions),
                "suspicious_patterns": suspicious_patterns,
                "call_targets": call_targets[:20],
                "instructions": instructions,
                "disassembly_text": "\n".join(disasm_lines[:50])
            }

        except Exception as e:
            self.errors.append(f"Disassembly error: {e}")
            return {
                "status": "ERROR",
                "instructions": [],
                "disassembly_text": f"Error during entry-point disassembly: {e}"
            }
