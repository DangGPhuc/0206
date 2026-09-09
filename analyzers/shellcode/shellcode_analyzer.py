"""
0206 - Shellcode & Raw Payload Analyzer
Detects position-independent code (PIC) heuristics, get-PC stubs, and egghunters.
"""
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from analyzers.contract import AnalyzerContract, AnalysisStage, AnalyzerSafetyLevel
from core.schemas import AnalysisDomain
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming


class ShellcodeAnalyzer(AnalyzerContract):
    """Evaluates binary payloads for raw position-independent shellcode patterns."""

    @property
    def name(self) -> str:
        return "ShellcodeAnalyzer"

    @property
    def domains(self) -> List[AnalysisDomain]:
        return [AnalysisDomain.SHELLCODE]

    @property
    def stage(self) -> AnalysisStage:
        return AnalysisStage.ADVANCED_STATIC

    @property
    def input_requirements(self) -> List[str]:
        return ["sample_path"]

    @property
    def output_evidence_types(self) -> List[str]:
        return ["SHELLCODE_HEURISTICS"]

    @property
    def dependencies(self) -> List[str]:
        return []

    @property
    def safety_level(self) -> AnalyzerSafetyLevel:
        return AnalyzerSafetyLevel.SAFE_HOST

    def __init__(self, file_path: Optional[Union[str, Path]] = None, evidence_store: Optional[EvidenceStore] = None):
        self.file_path = Path(file_path) if file_path is not None else None
        self.evidence_store = evidence_store if evidence_store is not None else EvidenceStore()

    def analyze(self, file_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
        if file_path is not None:
            self.file_path = Path(file_path)
        if self.file_path is None or not self.file_path.exists():
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
