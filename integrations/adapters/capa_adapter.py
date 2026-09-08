"""
0206 - capa Integration Adapter (Tier 2 Open Source)
Executes capability detection via Mandiant capa if installed.
"""
from pathlib import Path
from typing import List, Optional
import shutil
import subprocess
import json

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from integrations.base import AnalyzerAdapter


class CapaAdapter(AnalyzerAdapter):
    name = "capa"
    version = "7.x"
    tier = "Tier 2 (Open Source)"
    capabilities = ["Capability Detection", "ATT&CK Mapping", "MBC Mapping"]

    def __init__(self, config_override: Optional[str] = None):
        super().__init__(config_override)
        self._cli_path = shutil.which(config_override or "capa")

    def available(self) -> bool:
        return self._cli_path is not None

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        p = Path(input_artifact)
        store = evidence_store if evidence_store is not None else EvidenceStore()

        if not self.available():
            rec = store.create(
                p.name, "CAPA", "status", "NOT_AVAILABLE",
                extractor=self.name, state=EvidenceState.NOT_AVAILABLE
            )
            records.append(rec)
            return records

        try:
            # Run capa in JSON mode with strict timeout
            cmd = [self._cli_path, "-j", str(p)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                data = json.loads(proc.stdout)
                rules = data.get("rules", {})
                for rule_name, rule_data in rules.items():
                    scope = rule_data.get("meta", {}).get("scope", "function")
                    rec = store.create(
                        p.name, "CAPA", f"capability_{rule_name}", f"Capability identified: {rule_name} (scope: {scope})",
                        extractor=self.name, state=EvidenceState.INFERRED,
                        provenance={"rule": rule_name, "meta": rule_data.get("meta", {})}
                    )
                    records.append(rec)
            else:
                rec = store.create(
                    p.name, "CAPA", "status", f"Capa completed with code {proc.returncode}",
                    extractor=self.name, state=EvidenceState.NOT_CONFIRMED
                )
                records.append(rec)
        except Exception as e:
            rec = store.create(
                p.name, "CAPA", "error", str(e),
                extractor=self.name, state=EvidenceState.NOT_CONFIRMED
            )
            records.append(rec)

        return records
