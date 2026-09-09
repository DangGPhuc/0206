"""
0206 - .NET CLR Assembly Analyzer
Detects whether binary target is a managed .NET CLR assembly.
"""
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
import pefile

from analyzers.contract import AnalyzerContract, AnalysisStage, AnalyzerSafetyLevel
from core.schemas import AnalysisDomain
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming


class DotNetAnalyzer(AnalyzerContract):
    """Detects .NET CLR runtime header and managed structures."""

    @property
    def name(self) -> str:
        return "DotNetAnalyzer"

    @property
    def domains(self) -> List[AnalysisDomain]:
        return [AnalysisDomain.DOTNET]

    @property
    def stage(self) -> AnalysisStage:
        return AnalysisStage.ADVANCED_STATIC

    @property
    def input_requirements(self) -> List[str]:
        return ["sample_path"]

    @property
    def output_evidence_types(self) -> List[str]:
        return ["PE_METRICS"]

    @property
    def dependencies(self) -> List[str]:
        return ["pefile"]

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
            return {"status": "SKIPPED", "is_dotnet": False}

        hashes = hash_file_streaming(self.file_path)
        sha256 = hashes.get("sha256", "UNKNOWN")

        is_dotnet = False
        clr_version = "N/A"
        try:
            with open(self.file_path, "rb") as f:
                raw_bytes = f.read(65536)
            pe = pefile.PE(data=raw_bytes, fast_load=True)
            # Check COM Descriptor Directory (DataDirectory[14])
            if hasattr(pe, 'OPTIONAL_HEADER') and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14:
                com_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
                if com_dir.VirtualAddress > 0 and com_dir.Size > 0:
                    is_dotnet = True
        except Exception:
            pass

        result = {
            "status": "COMPLETED",
            "is_dotnet": is_dotnet,
            "runtime": ".NET CLR" if is_dotnet else "Native Win32/x64"
        }

        if is_dotnet:
            self.evidence_store.create(
                self.file_path.name, "PE_METRICS", "is_dotnet_assembly", True,
                "DotNetAnalyzer", domain=AnalysisDomain.DOTNET, artifact_sha256=sha256,
                provenance={"runtime": ".NET CLR"}
            )
        return result
