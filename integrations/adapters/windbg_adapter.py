"""
0206 - WinDbg Integration Adapter (Tier 3 Proprietary/Windows)
Optional adapter for Microsoft Windows Debugger (WinDbg / cdb.exe) crash dump analysis.
Strictly optional: Never imported as a mandatory requirement.
"""
from pathlib import Path
from typing import List, Optional, Tuple
import shutil
import platform

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from integrations.base import AnalyzerAdapter, AdapterStatus


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

    def check_functional(self) -> Tuple[AdapterStatus, str]:
        if platform.system() != "Windows":
            return AdapterStatus.NOT_SUPPORTED, "WinDbg / cdb requires a Windows host environment."
        if not self.available():
            return AdapterStatus.NOT_INSTALLED, "WinDbg / cdb binary not found in PATH."
        return AdapterStatus.READY, f"WinDbg/cdb binary detected at {self._bin_path}"

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None, **kwargs) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        p = Path(input_artifact)
        store = evidence_store if evidence_store is not None else EvidenceStore()

        if not self.available():
            status_state = EvidenceState.NOT_AVAILABLE if platform.system() == "Windows" else EvidenceState.NOT_ANALYZED
            rec = store.create(
                p.name, "WINDBG", "status",
                f"WinDbg is {'not installed' if platform.system() == 'Windows' else 'not supported on this OS'}",
                extractor=self.name, state=status_state
            )
            records.append(rec)
            return records

        rec = store.create(
            p.name, "WINDBG", "engine_status", "WinDbg debugger bridge available for crash dump analysis",
            extractor=self.name, state=EvidenceState.OBSERVED,
            provenance={"bin_path": self._bin_path}
        )
        records.append(rec)
        return records

