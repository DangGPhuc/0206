"""
0206 - Behavioral Telemetry Ingester & Event Normalizer
Normalizes disparate behavioral artifacts (Procmon CSV, Regshot Diff, Network PCAP, JSON telemetry)
into standard NormalizedEvent structures without depending strictly on any single proprietary tool.
"""
import os
import csv
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

from config import MAX_LOG_ROWS
from core.schemas import (
    AnalysisDomain, EvidenceState, EventType,
    NormalizedEvent, ProcessEvent, FileEvent, RegistryEvent, NetworkEvent
)
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming
from analyzers.network.pcap_analyzer import NetworkAnalyzer


class BehavioralAnalyzer:
    """
    Ingests and normalizes dynamic execution telemetry from multiple sources.
    Does not execute malware directly on host.
    """

    def __init__(
        self,
        pcap_path: Optional[str | Path] = None,
        procmon_path: Optional[str | Path] = None,
        regshot_path: Optional[str | Path] = None,
        json_path: Optional[str | Path] = None,
        evidence_store: Optional[EvidenceStore] = None
    ):
        self.pcap_path = Path(pcap_path) if pcap_path else None
        self.procmon_path = Path(procmon_path) if procmon_path else None
        self.regshot_path = Path(regshot_path) if regshot_path else None
        self.json_path = Path(json_path) if json_path else None
        self.evidence_store = evidence_store or EvidenceStore()
        self.normalized_events: List[NormalizedEvent] = []
        self.errors: List[str] = []

    def analyze(self) -> Dict[str, Any]:
        """Runs multi-artifact behavioral parsing and normalizes into standard events."""
        results: Dict[str, Any] = {
            "network": {},
            "processes": [],
            "files": {"created": [], "deleted": [], "written": []},
            "registry": {"persistence_keys": [], "modified": []},
            "normalized_event_count": 0,
            "errors": self.errors
        }

        # 1. PCAP Ingestion
        if self.pcap_path and self.pcap_path.exists():
            net_analyzer = NetworkAnalyzer(self.pcap_path, evidence_store=self.evidence_store)
            net_data = net_analyzer.analyze()
            results["network"] = net_data

        # 2. Procmon CSV Ingestion
        if self.procmon_path and self.procmon_path.exists():
            procmon_data = self._parse_procmon(self.procmon_path)
            results["processes"].extend(procmon_data.get("processes", []))
            results["files"]["created"].extend(procmon_data.get("files_created", []))
            results["files"]["written"].extend(procmon_data.get("files_written", []))
            results["registry"]["persistence_keys"].extend(procmon_data.get("persistence_keys", []))

        # 3. Regshot Diff Ingestion
        if self.regshot_path and self.regshot_path.exists():
            regshot_data = self._parse_regshot(self.regshot_path)
            results["registry"]["modified"].extend(regshot_data.get("keys_modified", []))

        results["normalized_event_count"] = len(self.normalized_events)
        return results

    def _parse_procmon(self, file_path: Path) -> Dict[str, Any]:
        """Parses Procmon CSV log into normalized events with row-limit safeguards."""
        hashes = hash_file_streaming(file_path)
        sha256 = hashes.get("sha256", "UNKNOWN")
        artifact_name = file_path.name

        procs = []
        files_created = []
        files_written = []
        pers_keys = []
        row_count = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    row_count += 1
                    if row_count > MAX_LOG_ROWS:
                        self.errors.append(f"Reached MAX_LOG_ROWS ({MAX_LOG_ROWS}) limit on Procmon log.")
                        break

                    proc_name = row.get("Process Name", "")
                    operation = row.get("Operation", "")
                    path_val = row.get("Path", "")
                    result_val = row.get("Result", "")
                    pid_str = row.get("PID", "0")
                    pid = int(pid_str) if pid_str.isdigit() else None

                    # Process Activity
                    if operation in ("Process Create", "Process Start"):
                        evt = ProcessEvent(
                            event_id=f"EVT-PROC-{row_count}",
                            event_type=EventType.PROCESS_CREATE,
                            process_name=proc_name,
                            pid=pid,
                            source="PROCMON",
                            artifact_hash=sha256,
                            target_path=path_val,
                            provenance={"row_index": row_count}
                        )
                        self.normalized_events.append(evt)
                        if proc_name not in procs:
                            procs.append(proc_name)
                            self.evidence_store.create(
                                artifact_name, "PROCMON_PROCESS", "process_spawn", proc_name,
                                "BehavioralAnalyzer", artifact_sha256=sha256, domain=AnalysisDomain.PROCESS,
                                source_line=row_count, provenance={"path": path_val, "pid": pid}
                            )

                    # File Activity
                    elif "CreateFile" in operation or "WriteFile" in operation:
                        is_write = "WriteFile" in operation
                        evt_type = EventType.FILE_WRITE if is_write else EventType.FILE_CREATE
                        evt = FileEvent(
                            event_id=f"EVT-FILE-{row_count}",
                            event_type=evt_type,
                            process_name=proc_name,
                            pid=pid,
                            source="PROCMON",
                            artifact_hash=sha256,
                            file_path=path_val,
                            operation="WRITE" if is_write else "CREATE",
                            provenance={"row_index": row_count}
                        )
                        self.normalized_events.append(evt)

                        # Detect dropped executables or suspicious drops
                        if any(path_val.lower().endswith(ext) for ext in (".exe", ".dll", ".bin", ".vbs", ".ps1", ".bat")):
                            if path_val not in files_created:
                                files_created.append(path_val)
                                self.evidence_store.create(
                                    artifact_name, "PROCMON_FILE", "dropped_file", {"path": path_val, "writer": proc_name},
                                    "BehavioralAnalyzer", artifact_sha256=sha256, domain=AnalysisDomain.FILESYSTEM,
                                    source_line=row_count, provenance={"operation": operation, "path": path_val}
                                )

                    # Registry Persistence Activity
                    elif "RegSetValue" in operation or "RegCreateKey" in operation:
                        evt = RegistryEvent(
                            event_id=f"EVT-REG-{row_count}",
                            event_type=EventType.REGISTRY_WRITE,
                            process_name=proc_name,
                            pid=pid,
                            source="PROCMON",
                            artifact_hash=sha256,
                            key_path=path_val,
                            operation=operation,
                            provenance={"row_index": row_count}
                        )
                        self.normalized_events.append(evt)

                        if "CurrentVersion\\Run" in path_val or "Windows\\CurrentVersion\\RunOnce" in path_val:
                            if path_val not in pers_keys:
                                pers_keys.append(path_val)
                                self.evidence_store.create(
                                    artifact_name, "PROCMON_REG", "registry_persistence", {"key_path": path_val, "actor": proc_name},
                                    "BehavioralAnalyzer", artifact_sha256=sha256, domain=AnalysisDomain.PERSISTENCE,
                                    source_line=row_count, provenance={"operation": operation, "key_path": path_val}
                                )

        except Exception as e:
            self.errors.append(f"Error parsing Procmon CSV: {e}")

        return {
            "processes": procs,
            "files_created": files_created,
            "files_written": files_written,
            "persistence_keys": pers_keys
        }

    def _parse_regshot(self, file_path: Path) -> Dict[str, Any]:
        """Parses standard Regshot plaintext diff into normalized registry events."""
        hashes = hash_file_streaming(file_path)
        sha256 = hashes.get("sha256", "UNKNOWN")
        artifact_name = file_path.name

        modified_keys = []
        is_mod_section = False
        line_idx = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_idx += 1
                    sline = line.strip()
                    if not sline:
                        continue
                    if "Keys added:" in sline or "Values added:" in sline or "Values modified:" in sline:
                        is_mod_section = True
                        continue
                    if sline.startswith("---------"):
                        is_mod_section = False
                        continue

                    if is_mod_section and (sline.startswith("HKLM\\") or sline.startswith("HKCU\\")):
                        modified_keys.append(sline)
                        evt = RegistryEvent(
                            event_id=f"EVT-REGSHOT-{line_idx}",
                            event_type=EventType.REGISTRY_WRITE,
                            source="REGSHOT",
                            artifact_hash=sha256,
                            key_path=sline,
                            operation="REGSHOT_DIFF",
                            provenance={"line": line_idx}
                        )
                        self.normalized_events.append(evt)

                        if "CurrentVersion\\Run" in sline or "RunOnce" in sline:
                            self.evidence_store.create(
                                artifact_name, "REGSHOT_MODIFIED", "registry_persistence", {"key_path": sline},
                                "BehavioralAnalyzer", artifact_sha256=sha256, domain=AnalysisDomain.PERSISTENCE,
                                source_line=line_idx, provenance={"key_path": sline}
                            )

        except Exception as e:
            self.errors.append(f"Error parsing Regshot diff: {e}")

        return {"keys_modified": modified_keys}
