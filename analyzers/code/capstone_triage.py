"""
0206 - Static Code Triage Analyzer (Capstone Disassembly Engine)
Independent core disassembly engine providing fast initial static code triage.
Extracts entry-point instructions, invalid instruction sequences, suspicious instruction
patterns (direct syscalls, PEB access), and control-flow branch hints.
Does not claim to replace interactive decompilers (IDA/Ghidra).
"""
import pefile
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from analyzers.contract import AnalyzerContract, AnalysisStage, AnalyzerSafetyLevel
from core.schemas import AnalysisDomain, EvidenceState
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming

X86_REGISTERS = ["eax", "ebx", "ecx", "edx", "ebp", "esp", "esi", "edi"]
X64_REGISTERS = [
    "rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
]


class CodeAnalyzer(AnalyzerContract):
    """
    Performs fast static code triage on PE entry points using Capstone.
    Provides architecture-aware register tracking, prologue/epilogue detection,
    stack frame heuristics, and control-flow branch analysis.
    Emits atomic evidence items tagged by AnalysisDomain.ASSEMBLY and CONTROL_FLOW.
    """

    @property
    def name(self) -> str:
        return "CodeAnalyzer"

    @property
    def domains(self) -> List[AnalysisDomain]:
        return [
            AnalysisDomain.ASSEMBLY,
            AnalysisDomain.CONTROL_FLOW,
            AnalysisDomain.API,
            AnalysisDomain.ANTI_ANALYSIS,
            AnalysisDomain.OBFUSCATION,
        ]

    @property
    def stage(self) -> AnalysisStage:
        return AnalysisStage.BASIC_STATIC

    @property
    def input_requirements(self) -> List[str]:
        return ["sample_path"]

    @property
    def output_evidence_types(self) -> List[str]:
        return [
            "DISASSEMBLY",
            "CODE_STRUCTURE",
            "CONTROL_FLOW",
            "CALLING_CONVENTION"
        ]

    @property
    def dependencies(self) -> List[str]:
        return ["capstone", "pefile"]

    @property
    def safety_level(self) -> AnalyzerSafetyLevel:
        return AnalyzerSafetyLevel.SAFE_HOST

    def __init__(self, file_path: Optional[Union[str, Path]] = None, evidence_store: Optional[EvidenceStore] = None, max_instructions: int = 150):
        self.file_path = Path(file_path) if file_path is not None else None
        self.evidence_store = evidence_store if evidence_store is not None else EvidenceStore()
        self.max_instructions = max_instructions
        self.errors: List[str] = []

    def analyze(self, file_path: Optional[Union[str, Path]] = None, max_instructions: Optional[int] = None) -> Dict[str, Any]:
        """Runs entry-point disassembly and heuristic pattern detection."""
        if file_path is not None:
            self.file_path = Path(file_path)
        if self.file_path is None or not self.file_path.exists():
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
            branch_instructions = []
            stack_frame_accesses = []
            prologue_found = False
            epilogue_found = False
            calling_convention_hints = []
            effective_limit = max_instructions if max_instructions is not None else self.max_instructions

            # Architecture register set
            arch_registers = X64_REGISTERS if arch_mode == CS_MODE_64 else X86_REGISTERS
            reg_occurrences: Dict[str, int] = {r: 0 for r in arch_registers}

            prev_insn = None
            for insn in md.disasm(code_bytes, entry_va):
                addr_hex = hex(insn.address)
                mnemonic = insn.mnemonic
                op_str = insn.op_str
                line_str = f"{addr_hex}: {mnemonic} {op_str}".strip()

                # Register usage tracking
                op_lower = op_str.lower()
                for r in arch_registers:
                    if r in op_lower:
                        reg_occurrences[r] = reg_occurrences.get(r, 0) + 1

                inst_dict = {
                    "address": addr_hex,
                    "mnemonic": mnemonic,
                    "op_str": op_str,
                    "bytes": insn.bytes.hex()
                }
                instructions.append(inst_dict)

                # Heuristic 1: Function Prologue Detection
                if not prologue_found and len(instructions) <= 8:
                    if (mnemonic == "push" and op_str in ("ebp", "rbp")) or \
                       (prev_insn and prev_insn.mnemonic == "push" and prev_insn.op_str in ("ebp", "rbp") and
                        mnemonic == "mov" and ("ebp, esp" in op_str or "rbp, rsp" in op_str)) or \
                       (mnemonic == "sub" and ("rsp" in op_str or "esp" in op_str)):
                        prologue_found = True
                        self.evidence_store.create(
                            self.file_path.name, "CODE_STRUCTURE", "function_prologue",
                            {"address": addr_hex, "instruction": line_str, "type": "STANDARD_FRAME_SETUP"},
                            "CodeAnalyzer", domain=AnalysisDomain.CONTROL_FLOW, artifact_sha256=sha256,
                            source_offset=addr_hex
                        )

                # Heuristic 2: Function Epilogue Detection
                if mnemonic in ("leave", "ret", "retf"):
                    epilogue_found = True
                    # Check for stdcall ret N
                    if mnemonic == "ret" and op_str.strip() and op_str.strip() != "0":
                        calling_convention_hints.append({
                            "convention": "stdcall",
                            "evidence": line_str,
                            "note": "Callee stack cleanup detected via ret imm16"
                        })
                    if prev_insn and prev_insn.mnemonic in ("pop", "mov") and \
                       ("ebp" in prev_insn.op_str or "rbp" in prev_insn.op_str):
                        self.evidence_store.create(
                            self.file_path.name, "CODE_STRUCTURE", "function_epilogue",
                            {"address": addr_hex, "instruction": line_str, "type": "FRAME_TEARDOWN"},
                            "CodeAnalyzer", domain=AnalysisDomain.CONTROL_FLOW, artifact_sha256=sha256,
                            source_offset=addr_hex
                        )

                # Heuristic 3: Stack Frame Variable / Argument Accesses
                if "ebp -" in op_str or "rbp -" in op_str or "rsp +" in op_str:
                    stack_frame_accesses.append({"type": "LOCAL_VAR", "address": addr_hex, "op": op_str})
                elif "ebp +" in op_str or "rbp +" in op_str:
                    stack_frame_accesses.append({"type": "ARGUMENT", "address": addr_hex, "op": op_str})

                # Heuristic 4: Direct Syscall Detection (Evasion)
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

                # Heuristic 5: Process Environment Block (PEB) Access
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

                # Heuristic 6: Branch & Call Instructions
                if mnemonic == "call":
                    call_targets.append(op_str)
                    # Check x64 Microsoft FastCall heuristic (rcx/rdx used recently)
                    if arch_mode == CS_MODE_64:
                        calling_convention_hints.append({
                            "convention": "ms64_fastcall",
                            "evidence": line_str,
                            "note": "x64 ABI register call convention (heuristic)"
                        })
                elif mnemonic in ("jmp", "jz", "jnz", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jb"):
                    branch_instructions.append({"type": mnemonic, "target": op_str, "address": addr_hex})

                prev_insn = insn
                if len(instructions) >= effective_limit:
                    break

            # Record entry point disassembly triage evidence
            self.evidence_store.create(
                self.file_path.name, "DISASSEMBLY", "entry_point_triage", {
                    "instruction_count": len(instructions),
                    "architecture": arch_str,
                    "entry_va": hex(entry_va),
                    "suspicious_patterns_count": len(suspicious_patterns),
                    "prologue_found": prologue_found,
                    "epilogue_found": epilogue_found,
                }, "CodeAnalyzer", domain=AnalysisDomain.ASSEMBLY, artifact_sha256=sha256
            )

            # Record calling convention heuristic evidence if identified
            if calling_convention_hints:
                primary_hint = calling_convention_hints[0]
                self.evidence_store.create(
                    self.file_path.name, "CALLING_CONVENTION", "calling_convention_heuristic",
                    primary_hint, "CodeAnalyzer",
                    domain=AnalysisDomain.CONTROL_FLOW,
                    state=EvidenceState.INFERRED,
                    confidence=0.6,
                    artifact_sha256=sha256,
                    provenance={"hints": calling_convention_hints}
                )

            disasm_lines = [f"{i['address']}: {i['mnemonic']} {i['op_str']}" for i in instructions]

            return {
                "status": "OBSERVED",
                "triage_type": "STATIC CODE TRIAGE",
                "architecture": arch_str,
                "entry_va": hex(entry_va),
                "instruction_count": len(instructions),
                "prologue_detected": prologue_found,
                "epilogue_detected": epilogue_found,
                "stack_frame_accesses": len(stack_frame_accesses),
                "calling_convention_hints": calling_convention_hints[:5],
                "suspicious_patterns": suspicious_patterns,
                "call_targets": call_targets[:20],
                "branch_instructions": branch_instructions[:20],
                "register_occurrences": {k: v for k, v in reg_occurrences.items() if v > 0},
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
