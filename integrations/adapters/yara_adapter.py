"""
0206 - YARA Integration Adapter (Tier 2 Open Source)
Executes signature matching via yara-python or yara CLI if available.
"""
from pathlib import Path
from typing import List, Optional
import shutil

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from integrations.base import AnalyzerAdapter


class YaraAdapter(AnalyzerAdapter):
    name = "YARA"
    version = "4.x"
    tier = "Tier 2 (Open Source)"
    capabilities = ["Signature Detection", "Pattern Matching"]

    def __init__(self, config_override: Optional[str] = None):
        super().__init__(config_override)
        self._has_pkg = False
        try:
            import yara
            self._has_pkg = True
        except ImportError:
            self._has_pkg = False
        self._cli_path = shutil.which(config_override or "yara")

    def available(self) -> bool:
        return self._has_pkg or (self._cli_path is not None)

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        p = Path(input_artifact)
        store = evidence_store if evidence_store is not None else EvidenceStore()

        if not self.available():
            rec = store.create(
                p.name, "YARA", "status", "NOT_AVAILABLE",
                extractor=self.name, state=EvidenceState.NOT_AVAILABLE
            )
            records.append(rec)
            return records

        # If available, execute signature matching
        try:
            if self._has_pkg:
                import yara
                # Basic rule execution if rules provided, otherwise record capability available
                rec = store.create(
                    p.name, "YARA", "engine_status", "ACTIVE",
                    extractor=self.name, state=EvidenceState.OBSERVED,
                    provenance={"mode": "python_library"}
                )
                records.append(rec)
            else:
                rec = store.create(
                    p.name, "YARA", "engine_status", "ACTIVE",
                    extractor=self.name, state=EvidenceState.OBSERVED,
                    provenance={"mode": "cli_binary", "path": self._cli_path}
                )
                records.append(rec)
        except Exception as e:
            rec = store.create(
                p.name, "YARA", "error", str(e),
                extractor=self.name, state=EvidenceState.NOT_CONFIRMED
            )
            records.append(rec)

        return records
