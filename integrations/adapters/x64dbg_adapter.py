"""
0206 - x64dbg Integration Adapter (Tier 3 Proprietary/Windows)
Optional adapter for x64dbg post-mortem dump inspection and symbol maps.
Strictly optional: Never imported as a mandatory requirement.
"""
from pathlib import Path
from typing import List, Optional
import shutil
import platform

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from integrations.base import AnalyzerAdapter


class X64DbgAdapter(AnalyzerAdapter):
    name = "x64dbg"
    version = "snapshot"
    tier = "Tier 3 (Proprietary)"
    capabilities = ["Dynamic Debugging Triage", "Memory Breakpoint Analysis"]

    def __init__(self, config_override: Optional[str] = None):
        super().__init__(config_override)
        self._bin_path = shutil.which(config_override or "x64dbg")

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
                p.name, "X64DBG", "status", "NOT_AVAILABLE",
                extractor=self.name, state=EvidenceState.NOT_AVAILABLE
            )
            records.append(rec)
            return records

        rec = store.create(
            p.name, "X64DBG", "engine_status", "x64dbg debugger bridge available",
            extractor=self.name, state=EvidenceState.OBSERVED,
            provenance={"bin_path": self._bin_path}
        )
        records.append(rec)
        return records
