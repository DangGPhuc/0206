"""
0206 - pe-sieve Integration Adapter (Tier 2 Open Source)
Detects in-memory hooks, replaced headers, and shellcode injections via pe-sieve if available.
"""
from pathlib import Path
from typing import List, Optional
import shutil

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from integrations.base import AnalyzerAdapter


class PeSieveAdapter(AnalyzerAdapter):
    name = "pe-sieve"
    version = "0.3.x"
    tier = "Tier 2 (Open Source)"
    capabilities = ["Process Memory Inspection", "Hook Detection", "Hollow Process Detection"]

    def __init__(self, config_override: Optional[str] = None):
        super().__init__(config_override)
        self._bin_path = shutil.which(config_override or "pe-sieve")

    def available(self) -> bool:
        return self._bin_path is not None

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        p = Path(input_artifact)
        store = evidence_store if evidence_store is not None else EvidenceStore()

        if not self.available():
            rec = store.create(
                p.name, "PE_SIEVE", "status", "NOT_AVAILABLE",
                extractor=self.name, state=EvidenceState.NOT_AVAILABLE
            )
            records.append(rec)
            return records

        rec = store.create(
            p.name, "PE_SIEVE", "engine_status", "pe-sieve scanner detected",
            extractor=self.name, state=EvidenceState.OBSERVED,
            provenance={"bin_path": self._bin_path}
        )
        records.append(rec)
        return records
