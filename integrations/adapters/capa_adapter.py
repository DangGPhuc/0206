"""
0206 - capa Integration Adapter (Tier 2 Open Source)
Executes capability detection via Mandiant capa if installed.
"""
from pathlib import Path
from typing import List, Optional, Tuple
import shutil
import json

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from core.process_guard import safe_run_process
from integrations.base import AnalyzerAdapter, AdapterStatus



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

    def check_functional(self) -> Tuple[AdapterStatus, str]:
        if not self.available():
            return AdapterStatus.NOT_INSTALLED, "Mandiant capa is not installed in PATH."
        res = safe_run_process([self._cli_path, "--version"], timeout_sec=10)
        if res.exit_code == 0:
            return AdapterStatus.FUNCTIONAL, f"capa is functional ({res.stdout.strip()})"
        return AdapterStatus.READY, f"capa binary detected at {self._cli_path}"

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None, **kwargs) -> List[EvidenceRecord]:
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
            # Run capa in JSON mode via safe_run_process (no shell, clean env)
            res = safe_run_process([self._cli_path, "-j", str(p)], timeout_sec=60)
            if res.exit_code == 0 and res.stdout:
                data = json.loads(res.stdout)
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
                    p.name, "CAPA", "status", f"Capa completed with code {res.exit_code}: {res.stderr[:200] if res.stderr else 'no output'}",
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

