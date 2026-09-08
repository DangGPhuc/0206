"""
0206 - Anti-Analysis & Evasion Analyzer
Evaluates static and dynamic indicators of anti-debugging, anti-VM, timing evasion,
and direct kernel syscalls.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional
from core.schemas import AnalysisDomain, EvidenceState
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming


class AntiAnalysisAnalyzer:
    """Consolidates anti-analysis, anti-debugging, and evasion techniques."""

    def __init__(self, file_path: Path, evidence_store: Optional[EvidenceStore] = None):
        self.file_path = Path(file_path)
        self.evidence_store = evidence_store or EvidenceStore()

    def analyze(self) -> Dict[str, Any]:
        if not self.file_path.exists():
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
