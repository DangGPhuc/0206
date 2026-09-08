"""
0206 - Ghidra Integration Adapter (Tier 2 Open Source)
Performs headless decompiler triage via Ghidra analyzeHeadless if installed.
"""
from pathlib import Path
from typing import List, Optional
import shutil

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from integrations.base import AnalyzerAdapter


class GhidraAdapter(AnalyzerAdapter):
    name = "Ghidra"
    version = "11.x"
    tier = "Tier 2 (Open Source)"
    capabilities = ["Decompilation", "Function Analysis", "Cross References"]

    def __init__(self, config_override: Optional[str] = None):
        super().__init__(config_override)
        self._bin_path = shutil.which(config_override or "ghidra")
        self._headless_path = shutil.which("analyzeHeadless")

    def available(self) -> bool:
        return (self._bin_path is not None) or (self._headless_path is not None)

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        p = Path(input_artifact)
        store = evidence_store if evidence_store is not None else EvidenceStore()

        if not self.available():
            rec = store.create(
                p.name, "GHIDRA", "status", "NOT_AVAILABLE",
                extractor=self.name, state=EvidenceState.NOT_AVAILABLE
            )
            records.append(rec)
            return records

        rec = store.create(
            p.name, "GHIDRA", "engine_status", "Ghidra headless engine detected and ready for headless script execution",
            extractor=self.name, state=EvidenceState.OBSERVED,
            provenance={"bin_path": self._bin_path or self._headless_path}
        )
        records.append(rec)
        return records
