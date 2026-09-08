"""
0206 - .NET CLR Assembly Analyzer
Detects whether binary target is a managed .NET CLR assembly.
"""
from pathlib import Path
from typing import Dict, Any, Optional
import pefile

from core.schemas import AnalysisDomain
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming


class DotNetAnalyzer:
    """Inspects PE structures for .NET CLR runtime metadata."""

    def __init__(self, file_path: Path, evidence_store: Optional[EvidenceStore] = None):
        self.file_path = Path(file_path)
        self.evidence_store = evidence_store or EvidenceStore()

    def analyze(self) -> Dict[str, Any]:
        if not self.file_path.exists():
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
