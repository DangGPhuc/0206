"""
0206 - WinDbg Integration Adapter (Tier 3 Proprietary/Windows)
Optional adapter for Microsoft Windows Debugger (WinDbg / cdb.exe) crash dump analysis.
Strictly optional: Never imported as a mandatory requirement.
"""
from pathlib import Path
from typing import List, Optional
import shutil
import platform

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from integrations.base import AnalyzerAdapter


class WinDbgAdapter(AnalyzerAdapter):
    name = "WinDbg"
    version = "10.x"
    tier = "Tier 3 (Proprietary)"
    capabilities = ["Crash Dump Triage", "Kernel Telemetry", "Symbol Resolution"]

    def __init__(self, config_override: Optional[str] = None):
        super().__init__(config_override)
        self._bin_path = shutil.which(config_override or "windbg") or shutil.which("cdb")

    def available(self) -> bool:
        if platform.system() != "Windows":
            return False
        return self._bin_path is not None

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        p = Path(input_artifact)
        store = evidence_store if evidence_store is not None else EvidenceStore()

        if not self.available():
            rec = store.create(
                p.name, "WINDBG", "status", "NOT_AVAILABLE",
                extractor=self.name, state=EvidenceState.NOT_AVAILABLE
            )
            records.append(rec)
            return records

        rec = store.create(
            p.name, "WINDBG", "engine_status", "WinDbg debugger bridge available",
            extractor=self.name, state=EvidenceState.OBSERVED,
            provenance={"bin_path": self._bin_path}
        )
        records.append(rec)
        return records
