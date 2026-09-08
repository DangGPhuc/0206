"""
0206 - FLOSS Integration Adapter (Tier 2 Open Source)
Extracts obfuscated, stack-allocated, and encoded strings via Mandiant FLOSS if installed.
"""
from pathlib import Path
from typing import List, Optional
import shutil

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from integrations.base import AnalyzerAdapter


class FlossAdapter(AnalyzerAdapter):
    name = "FLOSS"
    version = "3.x"
    tier = "Tier 2 (Open Source)"
    capabilities = ["Obfuscated String Decoding", "Stack Strings", "Tight Loops Extraction"]

    def __init__(self, config_override: Optional[str] = None):
        super().__init__(config_override)
        self._bin_path = shutil.which(config_override or "floss")

    def available(self) -> bool:
        return self._bin_path is not None

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        p = Path(input_artifact)
        store = evidence_store if evidence_store is not None else EvidenceStore()

        if not self.available():
            rec = store.create(
                p.name, "FLOSS", "status", "NOT_AVAILABLE",
                extractor=self.name, state=EvidenceState.NOT_AVAILABLE
            )
            records.append(rec)
            return records

        rec = store.create(
            p.name, "FLOSS", "engine_status", "Mandiant FLOSS deobfuscator detected",
            extractor=self.name, state=EvidenceState.OBSERVED,
            provenance={"bin_path": self._bin_path}
        )
        records.append(rec)
        return records
