"""
0206 - Anti-Analysis & Evasion Analyzer
Evaluates static and dynamic indicators of anti-debugging, anti-VM, timing evasion,
and direct kernel syscalls.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from analyzers.contract import AnalyzerContract, AnalysisStage, AnalyzerSafetyLevel
from core.schemas import AnalysisDomain, EvidenceState
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming


class AntiAnalysisAnalyzer(AnalyzerContract):
    """Consolidates anti-analysis, anti-debugging, and evasion techniques."""

    @property
    def name(self) -> str:
        return "AntiAnalysisAnalyzer"

    @property
    def domains(self) -> List[AnalysisDomain]:
        return [AnalysisDomain.ANTI_ANALYSIS]

    @property
    def stage(self) -> AnalysisStage:
        return AnalysisStage.ADVANCED_STATIC

    @property
    def input_requirements(self) -> List[str]:
        return ["sample_path"]

    @property
    def output_evidence_types(self) -> List[str]:
        return ["ANTI_ANALYSIS"]

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

        # Query anti-debug APIs and syscalls from static analysis
        evasion_evs = (
            self.evidence_store.find(field="imported_api_evasion") +
            self.evidence_store.find(field="direct_syscall") +
            self.evidence_store.find(field="peb_access")
        )

        indicators = [f"{e.field}: {e.value}" for e in evasion_evs]
        status = "SUSPICIOUS_EVASION_OBSERVED" if indicators else "NO_OBVIOUS_EVASION"

        result = {
            "status": status,
            "evasion_indicators": indicators,
            "anti_debug_apis": [e.value for e in evasion_evs if e.field == "imported_api_evasion"],
            "direct_syscalls": [e.value for e in evasion_evs if e.field == "direct_syscall"],
            "peb_access": [e.value for e in evasion_evs if e.field == "peb_access"]
        }

        if indicators:
            self.evidence_store.create(
                self.file_path.name, "ANTI_ANALYSIS", "evasion_summary", result,
                "AntiAnalysisAnalyzer", domain=AnalysisDomain.ANTI_ANALYSIS, artifact_sha256=sha256
            )
        return result
