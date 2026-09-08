"""
0206 - radare2 Integration Adapter (Tier 2 Open Source)
Extracts binary metadata, security mitigations, and symbols via rabin2 / r2 if installed.
"""
from pathlib import Path
from typing import List, Optional, Tuple
import shutil
import json

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from core.process_guard import safe_run_process
from integrations.base import AnalyzerAdapter, AdapterStatus


class Radare2Adapter(AnalyzerAdapter):
    name = "radare2"
    version = "5.x"
    tier = "Tier 2 (Open Source)"
    capabilities = ["Binary Inspection", "Security Mitigations", "Symbol Extraction"]

    def __init__(self, config_override: Optional[str] = None):
        super().__init__(config_override)
        self._r2_path = shutil.which(config_override or "radare2") or shutil.which("r2")
        self._rabin2_path = shutil.which("rabin2")

    def available(self) -> bool:
        return (self._r2_path is not None) or (self._rabin2_path is not None)

    def check_functional(self) -> Tuple[AdapterStatus, str]:
        if not self.available():
            return AdapterStatus.NOT_INSTALLED, "radare2 is not installed on the system."
        if self._rabin2_path:
            return AdapterStatus.READY, f"rabin2 utility ready at {self._rabin2_path}"
        return AdapterStatus.DETECTED, f"radare2 detected at {self._r2_path}"

    def analyze(
        self,
        input_artifact: Path,
        evidence_store: Optional[EvidenceStore] = None,
        **kwargs
    ) -> List[EvidenceRecord]:
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

        if not self._rabin2_path:
            rec = store.create(
                p.name, "RADARE2", "status", "rabin2 binary missing for automated batch inspection",
                extractor=self.name, state=EvidenceState.NOT_ANALYZED
            )
            records.append(rec)
            return records

        # Run rabin2 -I -j (binary info in JSON)
        cmd = [self._rabin2_path, "-I", "-j", str(p)]
        proc = safe_run_process(cmd, timeout=30)
        if proc.exit_code == 0:
            try:
                data = json.loads(proc.stdout)
                info = data.get("info", {})
                rec = store.create(
                    p.name, "RADARE2_INFO", "binary_info", {
                        "arch": info.get("arch"),
                        "bits": info.get("bits"),
                        "os": info.get("os"),
                        "canary": info.get("canary"),
                        "nx": info.get("nx"),
                        "pic": info.get("pic"),
                        "stripped": info.get("stripped")
                    },
                    extractor=self.name, state=EvidenceState.OBSERVED,
                    provenance={"cmd": cmd, "compiler": info.get("compiler")}
                )
                records.append(rec)
            except Exception as ex:
                rec = store.create(
                    p.name, "RADARE2", "parse_error", str(ex),
                    extractor=self.name, state=EvidenceState.NOT_CONFIRMED
                )
                records.append(rec)
        else:
            rec = store.create(
                p.name, "RADARE2", "error", proc.stderr[:200],
                extractor=self.name, state=EvidenceState.NOT_CONFIRMED
            )
            records.append(rec)

        return records
