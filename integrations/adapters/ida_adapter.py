"""
0206 - IDA Pro Integration Adapter (Tier 3 Proprietary)
Optional adapter for Hex-Rays IDA Pro / idat / ida64 batch analysis.
Strictly optional: Never imported as a mandatory requirement.
"""
from pathlib import Path
from typing import List, Optional
import shutil

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from integrations.base import AnalyzerAdapter


class IdaProAdapter(AnalyzerAdapter):
    name = "IDA Pro"
    version = "8.x/9.x"
    tier = "Tier 3 (Proprietary)"
    capabilities = ["Interactive Disassembly", "Hex-Rays Decompilation", "Type Recovery"]

    def __init__(self, config_override: Optional[str] = None):
        super().__init__(config_override)
        self._bin_path = shutil.which(config_override or "ida64") or shutil.which("idat64") or shutil.which("ida")

    def available(self) -> bool:
        return self._bin_path is not None

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        p = Path(input_artifact)
        store = evidence_store if evidence_store is not None else EvidenceStore()

        if not self.available():
            rec = store.create(
                p.name, "IDA_PRO", "status", "NOT_AVAILABLE",
                extractor=self.name, state=EvidenceState.NOT_AVAILABLE
            )
            records.append(rec)
            return records

        rec = store.create(
            p.name, "IDA_PRO", "engine_status", "IDA Pro binary detected and configured for batch headless triage",
            extractor=self.name, state=EvidenceState.OBSERVED,
            provenance={"bin_path": self._bin_path}
        )
        records.append(rec)
        return records
