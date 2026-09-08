"""
0206 - YARA Integration Adapter (Tier 2 Open Source)
Executes signature matching via yara-python or yara CLI when rules are provided.
Never claims malware is detected merely because YARA is installed.
If no ruleset is supplied, reports ruleset status as NOT_ANALYZED.
"""
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
import shutil

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from core.process_guard import safe_run_process
from integrations.base import AnalyzerAdapter, AdapterStatus


class YaraAdapter(AnalyzerAdapter):
    name = "YARA"
    version = "4.x"
    tier = "Tier 2 (Open Source)"
    capabilities = ["Signature Detection", "Pattern Matching"]

    def __init__(self, config_override: Optional[str] = None, rules_path: Optional[Path | str] = None):
        super().__init__(config_override)
        self.rules_path = Path(rules_path) if rules_path else None
        self._has_pkg = False
        try:
            import yara
            self._has_pkg = True
        except ImportError:
            self._has_pkg = False
        self._cli_path = shutil.which(config_override or "yara")

    def available(self) -> bool:
        return self._has_pkg or (self._cli_path is not None)

    def check_functional(self) -> Tuple[AdapterStatus, str]:
        if not self.available():
            return AdapterStatus.NOT_INSTALLED, "YARA is not installed (neither yara-python nor yara CLI found)."
        if not self.rules_path or not self.rules_path.exists():
            return AdapterStatus.READY, "YARA engine detected, but no rule set provided via --yara-rules. Ruleset status: NOT_ANALYZED."
        return AdapterStatus.FUNCTIONAL, f"YARA ready with ruleset: {self.rules_path.name}"

    def analyze(
        self,
        input_artifact: Path,
        evidence_store: Optional[EvidenceStore] = None,
        **kwargs
    ) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        p = Path(input_artifact)
        store = evidence_store if evidence_store is not None else EvidenceStore()

        active_rules = Path(kwargs.get("rules_path", self.rules_path)) if kwargs.get("rules_path") or self.rules_path else None

        if not self.available():
            rec = store.create(
                p.name, "YARA", "status", "NOT_AVAILABLE",
                extractor=self.name, state=EvidenceState.NOT_AVAILABLE
            )
            records.append(rec)
            return records

        if not active_rules or not active_rules.exists():
            # YARA is installed, but no ruleset was provided -> Explicitly record NOT_ANALYZED
            rec = store.create(
                p.name, "YARA", "ruleset_status", "MISSING_RULESET (No --yara-rules provided)",
                extractor=self.name, state=EvidenceState.NOT_ANALYZED,
                provenance={"engine": "yara-python" if self._has_pkg else "yara-cli"}
            )
            records.append(rec)
            return records

        # Real Rule Execution
        try:
            if self._has_pkg:
                import yara
                rules = yara.compile(filepath=str(active_rules))
                matches = rules.match(str(p))

                for m in matches:
                    rec = store.create(
                        p.name, "YARA_MATCH", "rule_match", m.rule,
                        extractor=self.name, state=EvidenceState.OBSERVED,
                        confidence=0.95,
                        provenance={
                            "rule_name": m.rule,
                            "tags": list(m.tags),
                            "meta": m.meta,
                            "matched_strings_count": len(m.strings),
                            "ruleset_file": active_rules.name
                        }
                    )
                    records.append(rec)

                if not matches:
                    rec = store.create(
                        p.name, "YARA_SCAN", "scan_result", "NO_RULES_MATCHED",
                        extractor=self.name, state=EvidenceState.OBSERVED,
                        confidence=1.0,
                        provenance={"ruleset_file": active_rules.name}
                    )
                    records.append(rec)

            elif self._cli_path:
                # Execute CLI securely via safe_run_process
                cmd = [self._cli_path, "-m", "-s", str(active_rules), str(p)]
                proc = safe_run_process(cmd, timeout=45)
                if proc.exit_code == 0:
                    matched_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
                    for line in matched_lines:
                        parts = line.split()
                        rule_name = parts[0] if parts else line
                        rec = store.create(
                            p.name, "YARA_MATCH", "rule_match", rule_name,
                            extractor=self.name, state=EvidenceState.OBSERVED,
                            confidence=0.95,
                            provenance={"raw_match": line, "ruleset_file": active_rules.name}
                        )
                        records.append(rec)
                else:
                    rec = store.create(
                        p.name, "YARA", "scan_error", proc.stderr[:200],
                        extractor=self.name, state=EvidenceState.NOT_CONFIRMED
                    )
                    records.append(rec)

        except Exception as e:
            rec = store.create(
                p.name, "YARA", "error", str(e),
                extractor=self.name, state=EvidenceState.NOT_CONFIRMED
            )
            records.append(rec)

        return records
