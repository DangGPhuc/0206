"""
0206 - FLOSS Integration Adapter (Tier 2 Open Source)
Extracts obfuscated, stack-allocated, and encoded strings via Mandiant FLOSS if installed.
"""
from pathlib import Path
from typing import List, Optional, Tuple
import shutil

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from core.process_guard import safe_run_process
from integrations.base import AnalyzerAdapter, AdapterStatus


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

    def check_functional(self) -> Tuple[AdapterStatus, str]:
        if not self.available():
            return AdapterStatus.NOT_INSTALLED, "Mandiant FLOSS is not installed in PATH."
        res = safe_run_process([self._bin_path, "--version"], timeout_sec=10)
        if res.exit_code == 0:
            return AdapterStatus.FUNCTIONAL, f"FLOSS is functional ({res.stdout.strip()[:60]})"
        return AdapterStatus.READY, f"FLOSS binary detected at {self._bin_path}"

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None, **kwargs) -> List[EvidenceRecord]:
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

        try:
            # Run FLOSS with bounded execution
            res = safe_run_process([self._bin_path, "-q", str(p)], timeout_sec=60)
            if res.exit_code == 0 and res.stdout:
                extracted_lines = [line.strip() for line in res.stdout.splitlines() if len(line.strip()) >= 4]
                sample_strings = extracted_lines[:50]
                rec = store.create(
                    p.name, "FLOSS", "decoded_strings",
                    f"Extracted {len(extracted_lines)} strings (showing up to 50)",
                    extractor=self.name, state=EvidenceState.OBSERVED,
                    provenance={
                        "count": len(extracted_lines),
                        "sample": sample_strings,
                        "stdout_sha256": res.stdout_sha256
                    }
                )
                records.append(rec)
            else:
                rec = store.create(
                    p.name, "FLOSS", "status", f"FLOSS exited with code {res.exit_code}: {res.stderr[:200] if res.stderr else 'no output'}",
                    extractor=self.name, state=EvidenceState.NOT_CONFIRMED
                )
                records.append(rec)
        except Exception as e:
            rec = store.create(
                p.name, "FLOSS", "error", str(e),
                extractor=self.name, state=EvidenceState.NOT_CONFIRMED
            )
            records.append(rec)

        return records

