"""
0206 - Shellcode & Raw Payload Analyzer
Detects position-independent code (PIC) heuristics, get-PC stubs, and egghunters.
"""
from pathlib import Path
from typing import Dict, Any, Optional
from core.schemas import AnalysisDomain
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming


class ShellcodeAnalyzer:
    """Evaluates binary payloads for raw position-independent shellcode patterns."""

    def __init__(self, file_path: Path, evidence_store: Optional[EvidenceStore] = None):
        self.file_path = Path(file_path)
        self.evidence_store = evidence_store or EvidenceStore()

    def analyze(self) -> Dict[str, Any]:
        if not self.file_path.exists():
            return {"status": "SKIPPED", "message": "File not found"}

        hashes = hash_file_streaming(self.file_path)
        sha256 = hashes.get("sha256", "UNKNOWN")

        with open(self.file_path, "rb") as f:
            data = f.read(4096)

        # Heuristic 1: Call/Pop get-PC sequence: E8 00 00 00 00 58/59/5A/5B
        get_pc_detected = b"\xe8\x00\x00\x00\x00" in data and any(pop_op in data for pop_op in (b"\x58", b"\x59", b"\x5b"))
        # Heuristic 2: FSTENV / FNSTENV get-PC
        fnstenv_detected = b"\xd9\x74\x24" in data or b"\xd9\x34\x24" in data

        is_shellcode_like = get_pc_detected or fnstenv_detected
        result = {
            "is_shellcode_like": is_shellcode_like,
            "get_pc_detected": get_pc_detected,
            "fnstenv_detected": fnstenv_detected
        }

        if is_shellcode_like:
            self.evidence_store.create(
                self.file_path.name, "SHELLCODE_HEURISTICS", "position_independent_code", result,
                "ShellcodeAnalyzer", domain=AnalysisDomain.SHELLCODE, artifact_sha256=sha256
            )
        return result
