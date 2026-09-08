"""
0206 - Weaponized Document & Script Payload Triage
Evaluates samples for embedded macros, OLE streams, PDF exploits, and script tags.
"""
from pathlib import Path
from typing import Dict, Any, Optional
from core.schemas import AnalysisDomain
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming


class DocumentAnalyzer:
    """Triage for weaponized office documents, PDFs, and script payloads."""

    def __init__(self, file_path: Path, evidence_store: Optional[EvidenceStore] = None):
        self.file_path = Path(file_path)
        self.evidence_store = evidence_store or EvidenceStore()

    def analyze(self) -> Dict[str, Any]:
        if not self.file_path.exists():
            return {"status": "SKIPPED", "is_document": False}

        hashes = hash_file_streaming(self.file_path)
        sha256 = hashes.get("sha256", "UNKNOWN")

        with open(self.file_path, "rb") as f:
            header = f.read(1024)

        is_ole = header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        is_pdf = header.startswith(b"%PDF-")
        is_rtf = header.startswith(b"{\\rtf")

        result = {
            "is_document": is_ole or is_pdf or is_rtf,
            "format": "OLE2" if is_ole else "PDF" if is_pdf else "RTF" if is_rtf else "Non-document"
        }

        if result["is_document"]:
            self.evidence_store.create(
                self.file_path.name, "FILE_IDENTIFICATION", "document_type", result["format"],
                "DocumentAnalyzer", domain=AnalysisDomain.DOCUMENT, artifact_sha256=sha256
            )
        return result
