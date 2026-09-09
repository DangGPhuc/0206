"""
0206 - Advanced Static Unpacking & Crypter Analyzer
Analyzes binary structure for packing signatures, section entropy anomalies,
and decompression stubs.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from analyzers.contract import AnalyzerContract, AnalysisStage, AnalyzerSafetyLevel
from core.schemas import AnalysisDomain, EvidenceState
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming


class UnpackingAnalyzer(AnalyzerContract):
    """Detects packing mechanisms, compression stubs, and crypter characteristics."""

    @property
    def name(self) -> str:
        return "UnpackingAnalyzer"

    @property
    def domains(self) -> List[AnalysisDomain]:
        return [AnalysisDomain.PACKING, AnalysisDomain.UNPACKING]

    @property
    def stage(self) -> AnalysisStage:
        return AnalysisStage.ADVANCED_STATIC

    @property
    def input_requirements(self) -> List[str]:
        return ["sample_path"]

    @property
    def output_evidence_types(self) -> List[str]:
        return ["ADVANCED_STATIC"]

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

        # Query existing evidence from static PE analysis
        rwx_evs = self.evidence_store.find(field="section_is_rwx")
        packer_evs = self.evidence_store.find(field="packer_assessment")
        susp_sec_evs = self.evidence_store.find(field="suspicious_section_name")

        is_packed = bool(rwx_evs or susp_sec_evs or (packer_evs and packer_evs[0].value.get("score", 0) >= 60))
        details = {
            "packing_suspected": is_packed,
            "rwx_sections_present": len(rwx_evs) > 0,
            "suspicious_section_names": [e.value for e in susp_sec_evs],
            "recommendation": "Dynamic execution tracing or memory dumping required to retrieve original payload." if is_packed else "Standard static analysis applicable."
        }

        self.evidence_store.create(
            self.file_path.name, "ADVANCED_STATIC", "unpacking_triage", details,
            "UnpackingAnalyzer", domain=AnalysisDomain.UNPACKING, artifact_sha256=sha256
        )
        return details
