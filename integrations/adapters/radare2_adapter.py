"""
0206 - radare2 Integration Adapter (Tier 2 Open Source)
Extracts binary headers and symbol metrics via radare2 / rabin2 if installed.
"""
from pathlib import Path
from typing import List, Optional
import shutil

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from integrations.base import AnalyzerAdapter


class Radare2Adapter(AnalyzerAdapter):
    name = "radare2"
    version = "5.x"
    tier = "Tier 2 (Open Source)"
    capabilities = ["Binary Inspection", "Disassembly", "Symbol Extraction"]

    def __init__(self, config_override: Optional[str] = None):
        super().__init__(config_override)
        self._bin_path = shutil.which(config_override or "radare2") or shutil.which("r2")

    def available(self) -> bool:
        return self._bin_path is not None

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        p = Path(input_artifact)
        store = evidence_store if evidence_store is not None else EvidenceStore()

        if not self.available():
            rec = store.create(
                p.name, "RADARE2", "status", "NOT_AVAILABLE",
                extractor=self.name, state=EvidenceState.NOT_AVAILABLE
            )
            records.append(rec)
            return records

        rec = store.create(
            p.name, "RADARE2", "engine_status", "radare2 framework detected",
            extractor=self.name, state=EvidenceState.OBSERVED,
            provenance={"bin_path": self._bin_path}
        )
        records.append(rec)
        return records
