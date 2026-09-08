"""
0206 - IDA Pro Integration Adapter (Tier 3 Proprietary)
Optional adapter for Hex-Rays IDA Pro / idat / ida64 batch analysis.
Strictly optional: Never imported as a mandatory requirement.
Emits normalized evidence schemas for functions, xrefs, and decompiler outputs (Phase 10).
"""
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
import shutil
import hashlib

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from core.process_guard import safe_run_process
from integrations.base import AnalyzerAdapter, AdapterStatus


class IdaProAdapter(AnalyzerAdapter):
    name = "IDA Pro"
    version = "8.x/9.x"
    tier = "Tier 3 (Proprietary)"
    capabilities = ["Interactive Disassembly", "Hex-Rays Decompilation", "Type Recovery"]

    def __init__(self, config_override: Optional[str] = None):
        super().__init__(config_override)
        self._bin_path = (
            shutil.which(config_override) if config_override else None
        ) or shutil.which("idat64") or shutil.which("idat") or shutil.which("ida64") or shutil.which("ida")

    def available(self) -> bool:
        return self._bin_path is not None

    def check_functional(self) -> Tuple[AdapterStatus, str]:
        if not self.available():
            return AdapterStatus.NOT_INSTALLED, "IDA Pro binaries (ida64, idat64, ida) not detected in PATH."
        bin_name = Path(self._bin_path).name.lower()
        if "idat" in bin_name:
            return AdapterStatus.READY, f"IDA headless batch binary detected at {self._bin_path}"
        return AdapterStatus.DETECTED, f"IDA Pro GUI binary detected at {self._bin_path} (batch headless requires idat64/idat)"

    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None, **kwargs) -> List[EvidenceRecord]:
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

        script_path = kwargs.get("ida_script")
        if script_path and Path(script_path).is_file():
            # Batch headless script execution via safe_run_process
            try:
                # e.g.: idat64 -B -S"script.py" sample.exe
                args = [self._bin_path, "-B", f"-S{script_path}", str(p)]
                res = safe_run_process(args, timeout_sec=120)
                rec = store.create(
                    p.name, "IDA_PRO", "batch_analysis",
                    f"IDA Pro batch script executed (exit {res.exit_code})",
                    extractor=self.name, state=EvidenceState.OBSERVED if res.exit_code == 0 else EvidenceState.NOT_CONFIRMED,
                    provenance={"script": str(script_path), "stdout_sha256": res.stdout_sha256}
                )
                records.append(rec)
            except Exception as e:
                rec = store.create(
                    p.name, "IDA_PRO", "error", str(e),
                    extractor=self.name, state=EvidenceState.NOT_CONFIRMED
                )
                records.append(rec)
        else:
            # Capability detection only without false analysis claims
            rec = store.create(
                p.name, "IDA_PRO", "capability_status",
                "IDA Pro detected; batch script not specified. Standby for interactive or scripted disassembly.",
                extractor=self.name, state=EvidenceState.NOT_ANALYZED,
                provenance={"bin_path": self._bin_path}
            )
            records.append(rec)

        return records

    @staticmethod
    def normalize_function(
        func_name: str,
        address: str,
        size: int,
        source_tool: str = "IDA Pro",
        tool_version: str = "8.x/9.x"
    ) -> Dict[str, Any]:
        """Phase 10: Normalized function evidence schema."""
        return {
            "type": "FUNCTION",
            "function_name": func_name,
            "address": address,
            "size": size,
            "source_tool": source_tool,
            "tool_version": tool_version
        }

    @staticmethod
    def normalize_xref(
        source_function: str,
        target: str,
        address: str
    ) -> Dict[str, Any]:
        """Phase 10: Normalized cross-reference evidence schema."""
        return {
            "type": "CROSS_REFERENCE",
            "source_function": source_function,
            "target": target,
            "address": address
        }

    @staticmethod
    def normalize_decompiler_output(
        func_id: str,
        code_text: str,
        artifact_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """Phase 10: Normalized decompiler evidence schema with external artifact reference."""
        text_bytes = code_text.encode("utf-8")
        text_hash = hashlib.sha256(text_bytes).hexdigest()
        artifact_path = None
        if artifact_dir:
            artifact_dir = Path(artifact_dir)
            artifact_dir.mkdir(parents=True, exist_ok=True)
            out_file = artifact_dir / f"decomp_{func_id}_{text_hash[:8]}.c"
            out_file.write_text(code_text, encoding="utf-8")
            artifact_path = str(out_file)

        return {
            "type": "DECOMPILER",
            "function_id": func_id,
            "normalized_text_hash": text_hash,
            "artifact_path": artifact_path,
            "size": len(text_bytes)
        }

