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
        self.evidence_store = evidence_store if evidence_store is not None else EvidenceStore()
        self.normalized_events: List[NormalizedEvent] = []
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def parse_pcap(self) -> Dict[str, Any]:
        """Parses network PCAP file and returns network analysis dictionary."""
        if not self.pcap_path or not self.pcap_path.exists():
            return {
                "status": "NOT_ANALYZED",
                "packet_count": 0,
                "dns_queries": [],
                "http_requests": [],
                "tls_sni": [],
                "beacon_candidates": [],
                "c2_beacons": [],
                "errors": []
            }
        net_analyzer = NetworkAnalyzer(self.pcap_path, evidence_store=self.evidence_store)
        return net_analyzer.analyze()

    def parse_procmon_csv(self) -> Dict[str, Any]:
        """Parses Procmon CSV log into normalized events and structured host behavior."""
        results: Dict[str, Any] = {
            "status": "NOT_ANALYZED",
            "dropped_files": [],
            "persistence_registry": [],
            "spawned_processes": [],
            "normalized_events": [],
            "warnings": self.warnings
        }

        if not self.procmon_path or not self.procmon_path.exists():
            return results

        hashes = hash_file_streaming(self.procmon_path)
        sha256 = hashes.get("sha256", "UNKNOWN")
        artifact_name = self.procmon_path.name
        results["status"] = "OBSERVED"

        row_count = 0
        try:
            with open(self.procmon_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    row_count += 1
                    if row_count > MAX_LOG_ROWS:
                        msg = f"Reached MAX_LOG_ROWS ({MAX_LOG_ROWS}) limit on Procmon log."
                        self.warnings.append(msg)
                        results["warnings"].append(msg)
                        break

                    clean = {k.strip(): (v.strip() if v else "") for k, v in row.items() if k}
                    op = clean.get("Operation", "")
                    path_val = clean.get("Path", "")
                    proc = clean.get("Process Name", "")
                    detail = clean.get("Detail", "")
                    result = clean.get("Result", "")
                    pid_str = clean.get("PID", "0")
                    pid = int(pid_str) if pid_str.isdigit() else None

                    # Event Category mapping
                    event_category = "OTHER"
                    evt_type = EventType.PROCESS_CREATE
                    if op in ("CreateFile", "WriteFile"):
                        event_category = "FILE_WRITE" if op == "WriteFile" else "FILE_CREATE"
                        evt_type = EventType.FILE_WRITE if op == "WriteFile" else EventType.FILE_CREATE
                        evt = FileEvent(
                            event_id=f"EVT-FILE-{row_count}",
                            event_type=evt_type,
                            process_name=proc,
                            pid=pid,
                            source="PROCMON",
                            artifact_hash=sha256,
                            file_path=path_val,
                            operation="WRITE" if op == "WriteFile" else "CREATE",
                            provenance={"row_index": row_count}
                        )
                        self.normalized_events.append(evt)
                    elif op in ("RegSetValue", "RegCreateKey"):
                        event_category = "REGISTRY_WRITE" if op == "RegSetValue" else "REGISTRY_CREATE"
                        evt_type = EventType.REGISTRY_WRITE
                        evt = RegistryEvent(
                            event_id=f"EVT-REG-{row_count}",
                            event_type=evt_type,
                            process_name=proc,
                            pid=pid,
                            source="PROCMON",
                            artifact_hash=sha256,
                            key_path=path_val,
                            operation=op,
                            provenance={"row_index": row_count}
                        )
                        self.normalized_events.append(evt)
                    elif op in ("Process Create", "Process Start"):
                        event_category = "PROCESS_CREATE"
                        evt = ProcessEvent(
                            event_id=f"EVT-PROC-{row_count}",
                            event_type=EventType.PROCESS_CREATE,
                            process_name=proc,
                            pid=pid,
                            source="PROCMON",
                            artifact_hash=sha256,
                            target_path=path_val,
                            provenance={"row_index": row_count}
                        )
                        self.normalized_events.append(evt)

                    normalized_evt_dict = {
                        "event_id": f"EVT-{row_count:05d}",
                        "category": event_category,
                        "process": proc,
                        "operation": op,
                        "path": path_val,
                        "detail": detail,
                        "result": result
                    }
                    results["normalized_events"].append(normalized_evt_dict)

                    # 1. Dropped Files
                    if op in ("CreateFile", "WriteFile") and result == "SUCCESS":
                        lower_p = path_val.lower()
                        if any(ext in lower_p for ext in [".exe", ".dll", ".bat", ".vbs", ".ps1", ".scr", ".bin"]):
                            drop_item = {"process": proc, "path": path_val, "operation": op}
                            if drop_item not in results["dropped_files"]:
                                results["dropped_files"].append(drop_item)
                                self.evidence_store.create(
                                    artifact_name, "PROCMON_FILE", "dropped_file", drop_item,
                                    "BehavioralAnalyzer", artifact_sha256=sha256, domain=AnalysisDomain.FILESYSTEM,
                                    source_line=row_count, provenance={"row_index": row_count, "operation": op}
                                )

                    # 2. Registry Persistence
                    if op in ("RegSetValue", "RegCreateKey") and result == "SUCCESS":
                        lower_p = path_val.lower()
                        if any(k in lower_p for k in [
                            "currentversion\\run", "currentversion\\runonce",
                            "services\\", "winlogon", "appinit_dlls"
                        ]):
                            pers_item = {"process": proc, "key_path": path_val, "operation": op, "detail": detail}
                            if pers_item not in results["persistence_registry"]:
                                results["persistence_registry"].append(pers_item)
                                self.evidence_store.create(
                                    artifact_name, "PROCMON_REG", "registry_persistence", pers_item,
                                    "BehavioralAnalyzer", artifact_sha256=sha256, domain=AnalysisDomain.PERSISTENCE,
                                    source_line=row_count, provenance={"row_index": row_count, "operation": op}
                                )

                    # 3. Spawned Processes
                    if op in ("Process Create", "Process Start") and result == "SUCCESS":
                        proc_item = {"parent_process": proc, "command_line": detail, "path": path_val}
                        if proc_item not in results["spawned_processes"]:
                            results["spawned_processes"].append(proc_item)
                            self.evidence_store.create(
                                artifact_name, "PROCMON_PROC", "spawned_process", proc_item,
                                "BehavioralAnalyzer", artifact_sha256=sha256, domain=AnalysisDomain.PROCESS,
                                source_line=row_count, provenance={"row_index": row_count}
                            )

        except Exception as e:
            self.errors.append(f"Error parsing Procmon CSV: {e}")

        return results

    def _parse_procmon(self, file_path: Path) -> Dict[str, Any]:
        """Backward-compatible internal adapter."""
        return self.parse_procmon_csv()

    def parse_regshot(self) -> Dict[str, List[str]]:
        """Parses standard Regshot plaintext diff into keys added/modified."""
        if not self.regshot_path or not self.regshot_path.exists():
            return {"keys_added": [], "values_added": [], "files_added": []}
        reg_res = self._parse_regshot(self.regshot_path)
        return {
            "keys_added": reg_res.get("keys_modified", []),
            "values_added": [],
            "files_added": []
        }

    def analyze(self) -> Dict[str, Any]:
        """Runs multi-artifact behavioral parsing and normalizes into standard events."""
        pcap_data = self.parse_pcap()
        procmon_data = self.parse_procmon_csv()
        regshot_data = self.parse_regshot()

        results: Dict[str, Any] = {
            "network": pcap_data,
            "host_behavior": procmon_data,
            "regshot": regshot_data,
            "processes": [p["parent_process"] for p in procmon_data.get("spawned_processes", [])],
            "files": {
                "created": [f["path"] for f in procmon_data.get("dropped_files", []) if f.get("operation") == "CreateFile"],
                "deleted": [],
                "written": [f["path"] for f in procmon_data.get("dropped_files", []) if f.get("operation") == "WriteFile"]
            },
            "registry": {
                "persistence_keys": [r["key_path"] for r in procmon_data.get("persistence_registry", [])],
                "modified": regshot_data.get("keys_added", [])
            },
            "normalized_event_count": len(self.normalized_events),
            "normalized_events": self.normalized_events,
            "errors": self.errors,
            "warnings": self.warnings
        }
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
