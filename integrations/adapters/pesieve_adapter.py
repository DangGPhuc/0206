"""
0206 - pe-sieve Integration Adapter (Tier 2 Open Source)
Detects in-memory hooks, replaced headers, and shellcode injections via pe-sieve if available.
"""
from pathlib import Path
from typing import List, Optional, Tuple
import shutil

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from core.process_guard import safe_run_process
from integrations.base import AnalyzerAdapter, AdapterStatus


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

    def check_functional(self) -> Tuple[AdapterStatus, str]:
        if not self.available():
            return AdapterStatus.NOT_INSTALLED, "pe-sieve is not installed in PATH."
        res = safe_run_process([self._bin_path, "/version"], timeout_sec=10)
        if res.exit_code == 0:
            return AdapterStatus.FUNCTIONAL, f"pe-sieve is functional ({res.stdout.strip()[:60]})"
        return AdapterStatus.READY, f"pe-sieve binary detected at {self._bin_path}"

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None, **kwargs) -> List[EvidenceRecord]:
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

        target_pid = kwargs.get("pid")
        if target_pid:
            # Memory analysis mode for running process
            try:
                res = safe_run_process([self._bin_path, "/pid", str(target_pid), "/json"], timeout_sec=60)
                rec = store.create(
                    p.name, "PE_SIEVE", "process_inspection",
                    f"pe-sieve scanned PID {target_pid} (exit {res.exit_code})",
                    extractor=self.name, state=EvidenceState.OBSERVED,
                    provenance={"pid": target_pid, "stdout_sha256": res.stdout_sha256}
                )
                records.append(rec)
            except Exception as e:
                rec = store.create(
                    p.name, "PE_SIEVE", "error", str(e),
                    extractor=self.name, state=EvidenceState.NOT_CONFIRMED
                )
                records.append(rec)
        else:
            # Static file triage mode
            rec = store.create(
                p.name, "PE_SIEVE", "status",
                "pe-sieve is ready for memory/process triage; no target PID specified for static file",
                extractor=self.name, state=EvidenceState.NOT_ANALYZED,
                provenance={"bin_path": self._bin_path}
            )
            records.append(rec)

        return records

