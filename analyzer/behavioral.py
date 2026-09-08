"""
0206 - Behavioral Artifact Ingestion Module
Safely parses dynamic analysis artifacts using streaming readers:
- Network PCAP traces (Streaming Scapy PcapReader with memory bounds)
- Multi-factor composite Beacon Scoring (periodicity, jitter, packet size variance)
- Process Monitor (Procmon) CSV normalized event streaming
- Regshot diff parser
"""
import csv
import re
import math
import statistics
from pathlib import Path
from typing import Dict, List, Any, Optional
from scapy.all import PcapReader, DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw

from config import (
    MAX_PCAP_SIZE, MAX_PACKETS, MAX_LOG_ROWS,
    MAX_TRACKED_CONNECTIONS, MAX_TIMESTAMPS_PER_CONNECTION,
    BEACON_WEIGHTS
)
from core.evidence import EvidenceStore, EvidenceState



class BehavioralAnalyzer:
    """Ingests behavioral traces from sandbox runs or host/network monitors."""

    def __init__(
        self, 
        pcap_path: Optional[Path] = None, 
        procmon_path: Optional[Path] = None,
        regshot_path: Optional[Path] = None,
        evidence_store: Optional[EvidenceStore] = None
    ):
        self.pcap_path = Path(pcap_path) if pcap_path else None
        self.procmon_path = Path(procmon_path) if procmon_path else None
        self.regshot_path = Path(regshot_path) if regshot_path else None
        self.evidence_store = evidence_store if evidence_store is not None else EvidenceStore()
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def parse_pcap(self) -> Dict[str, Any]:
        """
        Parses network PCAP file in a memory-safe streaming fashion.
        Calculates multi-factor beacon scores and extracts DNS, HTTP, and TLS SNI.
        """
        results: Dict[str, Any] = {
            "status": "NOT_ANALYZED",
            "packet_count": 0,
            "analysis_limit_reached": False,
            "dns_queries": [],
            "http_requests": [],
            "tls_sni": [],
            "remote_ips": [],
            "c2_beacons": [],
            "warnings": []
        }

        if not self.pcap_path or not self.pcap_path.exists():
            return results

        file_size = self.pcap_path.stat().st_size
        if file_size > MAX_PCAP_SIZE:
            msg = f"PCAP size {file_size:,} bytes exceeds safety limit {MAX_PCAP_SIZE:,} bytes. Skipping."
            self.warnings.append(msg)
            results["warnings"].append(msg)
            return results

        artifact_name = self.pcap_path.name
        results["status"] = "OBSERVED"

        # Conversation tracking: {(dst_ip, dst_port): {"timestamps": [], "payload_sizes": []}}
        conversations: Dict[tuple, Dict[str, list]] = {}
        dns_map: Dict[str, List[str]] = {}
        http_requests: List[Dict[str, str]] = []
        tls_sni_list: List[str] = []
        ip_counts: Dict[str, int] = {}

        http_re = re.compile(rb'^(GET|POST|HEAD|PUT|DELETE|CONNECT)\s+([^\s]+)\s+HTTP/1\.[01]', re.IGNORECASE)
        host_re = re.compile(rb'(?i)Host:\s*([^\r\n]+)')
        ua_re = re.compile(rb'(?i)User-Agent:\s*([^\r\n]+)')

        packet_idx = 0
        try:
            with PcapReader(str(self.pcap_path)) as pcap_reader:
                for pkt in pcap_reader:
                    packet_idx += 1
                    if packet_idx > MAX_PACKETS:
                        results["analysis_limit_reached"] = True
                        self.warnings.append(f"Reached maximum packet analysis limit ({MAX_PACKETS}). Stopping streaming parse.")
                        break

                    # Timestamp
                    pkt_time = float(pkt.time)

                    # IP conversation tracking
                    if IP in pkt:
                        dst_ip = pkt[IP].dst
                        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                        
                        # Filter out local loopback/multicast
                        if not dst_ip.startswith(("127.", "255.", "224.", "0.")):
                            ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
                            key = (dst_ip, dport)
                            if key not in conversations:
                                if len(conversations) < MAX_TRACKED_CONNECTIONS:
                                    conversations[key] = {"timestamps": [], "payload_sizes": []}
                            if key in conversations:
                                if len(conversations[key]["timestamps"]) < MAX_TIMESTAMPS_PER_CONNECTION:
                                    conversations[key]["timestamps"].append(pkt_time)
                                    payload_len = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
                                    conversations[key]["payload_sizes"].append(payload_len)


                    # DNS Inspection
                    if pkt.haslayer(DNS):
                        dns = pkt[DNS]
                        if dns.qr == 0 and dns.qd:  # Query
                            qd_first = dns.qd[0] if isinstance(dns.qd, list) or hasattr(dns.qd, '__getitem__') else dns.qd
                            qname = qd_first.qname.decode('utf-8', errors='ignore').rstrip('.') if hasattr(qd_first, 'qname') else ""
                            if qname and qname not in dns_map:
                                dns_map[qname] = []
                        elif dns.qr == 1 and dns.an:  # Answer
                            qd_first = dns.qd[0] if (isinstance(dns.qd, list) or hasattr(dns.qd, '__getitem__')) and len(dns.qd) > 0 else dns.qd
                            qname = qd_first.qname.decode('utf-8', errors='ignore').rstrip('.') if hasattr(qd_first, 'qname') else ""
                            if qname:
                                if qname not in dns_map:
                                    dns_map[qname] = []
                                for i in range(len(dns.an)):
                                    an = dns.an[i]
                                    if hasattr(an, 'type') and an.type == 1:  # A record
                                        rdata = an.rdata
                                        if isinstance(rdata, str) and rdata not in dns_map[qname]:
                                            dns_map[qname].append(rdata)

                    # HTTP & TLS SNI
                    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                        payload = pkt[Raw].load
                        m = http_re.match(payload)
                        if m:
                            method = m.group(1).decode('ascii', errors='ignore')
                            uri = m.group(2).decode('ascii', errors='ignore')
                            host_m = host_re.search(payload)
                            ua_m = ua_re.search(payload)
                            host = host_m.group(1).decode('ascii', errors='ignore').strip() if host_m else ""
                            user_agent = ua_m.group(1).decode('ascii', errors='ignore').strip() if ua_m else ""

                            req_item = {
                                "method": method,
                                "uri": uri,
                                "host": host,
                                "user_agent": user_agent,
                                "dst_ip": pkt[IP].dst if IP in pkt else ""
                            }
                            if req_item not in http_requests:
                                http_requests.append(req_item)
                                self.evidence_store.create(
                                    artifact_name, "PCAP_HTTP", "http_request", req_item,
                                    "BehavioralAnalyzer", provenance={"packet_index": packet_idx}
                                )

                        # TLS SNI
                        if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                            try:
                                pos = payload.find(b'\x00\x00')
                                if pos != -1 and pos + 9 < len(payload):
                                    ext_len = int.from_bytes(payload[pos+7:pos+9], 'big')
                                    sni = payload[pos+9:pos+9+ext_len].decode('utf-8', errors='ignore')
                                    if sni and "." in sni and sni not in tls_sni_list:
                                        tls_sni_list.append(sni)
                                        self.evidence_store.create(
                                            artifact_name, "PCAP_TLS", "tls_sni", sni,
                                            "BehavioralAnalyzer", provenance={"packet_index": packet_idx}
                                        )
                            except Exception:
                                pass

        except Exception as e:
            self.errors.append(f"Error reading PCAP streaming packets: {e}")

        results["packet_count"] = packet_idx

        # Format DNS results & register evidence
        for domain, ips in dns_map.items():
            dns_entry = {"domain": domain, "resolved_ips": ips}
            results["dns_queries"].append(dns_entry)
            self.evidence_store.create(
                artifact_name, "PCAP_DNS", "dns_query", dns_entry, "BehavioralAnalyzer"
            )

        results["http_requests"] = http_requests[:30]
        results["tls_sni"] = tls_sni_list[:30]
        results["remote_ips"] = [
            {"ip": ip, "count": cnt} 
            for ip, cnt in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:30]
        ]

        # -------------------------------------------------------------
        # Multi-factor Composite Beacon Detection
        # -------------------------------------------------------------
        total_packets = max(1, packet_idx)
        beacons = []

        for (dst_ip, dst_port), data in conversations.items():
            tstamps = sorted(data["timestamps"])
            pkt_count = len(tstamps)

            # Need at least 3 intervals (4 packets) to analyze periodicity
            if pkt_count < 4:
                continue

            intervals = [tstamps[i+1] - tstamps[i] for i in range(len(tstamps)-1)]
            duration = tstamps[-1] - tstamps[0]
            avg_int = statistics.mean(intervals)
            median_int = statistics.median(intervals)
            std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
            jitter_ratio = (std_dev / avg_int) if avg_int > 0 else 1.0

            # 1. Periodicity Score (Low jitter -> high score)
            # If jitter_ratio < 0.1, periodicity score ~ 1.0; if jitter > 0.8, score ~ 0.1
            periodicity_score = max(0.0, min(1.0, 1.0 - (jitter_ratio / 0.8)))

            # 2. Destination Consistency Score
            destination_consistency_score = min(1.0, (pkt_count / total_packets) * 2.5)

            # 3. Interval Stability Score (median vs mean alignment)
            int_diff = abs(avg_int - median_int)
            stability_score = max(0.0, min(1.0, 1.0 - (int_diff / (avg_int + 0.001))))

            # 4. Packet Size Similarity Score
            sizes = data["payload_sizes"]
            size_std = statistics.stdev(sizes) if len(sizes) > 1 else 0.0
            size_mean = statistics.mean(sizes) if sizes else 0.0
            size_score = max(0.0, min(1.0, 1.0 - (size_std / (size_mean + 1.0))))

            # 5. Duration Score (Beacons persist over time)
            duration_score = min(1.0, duration / 60.0)

            # Weighted Composite Score
            beacon_score = (
                periodicity_score * BEACON_WEIGHTS["periodicity"] +
                destination_consistency_score * BEACON_WEIGHTS["destination_consistency"] +
                stability_score * BEACON_WEIGHTS["interval_stability"] +
                size_score * BEACON_WEIGHTS["packet_size_similarity"] +
                duration_score * BEACON_WEIGHTS["duration"]
            )
            beacon_score = round(beacon_score, 4)

            # Phase 15: Calibrated C2 / Beacon Terminology
            # Multi-source corroboration check (e.g. matched HTTP request to same destination)
            has_corroboration = any(
                req.get("dst_ip") == dst_ip or dst_ip in req.get("host", "")
                for req in http_requests
            )
            if beacon_score >= 0.85:
                cls = "CONFIRMED_C2" if has_corroboration else "LIKELY_C2_BEACON"
                ev_state = EvidenceState.OBSERVED if has_corroboration else EvidenceState.INFERRED
            elif beacon_score >= 0.60:
                cls = "SUSPECTED_BEACONING"
                ev_state = EvidenceState.INFERRED
            elif beacon_score >= 0.35:
                cls = "OBSERVED_PERIODIC_TRAFFIC"
                ev_state = EvidenceState.HEURISTIC
            else:
                cls = "NORMAL"
                ev_state = EvidenceState.OBSERVED

            candidate = {
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "packet_count": pkt_count,
                "duration_seconds": round(duration, 2),
                "avg_interval": round(avg_int, 3),
                "median_interval": round(median_int, 3),
                "std_dev_interval": round(std_dev, 3),
                "jitter_ratio": round(jitter_ratio, 3),
                "min_interval": round(min(intervals), 3),
                "max_interval": round(max(intervals), 3),
                "periodicity_score": round(periodicity_score, 3),
                "beacon_score": beacon_score,
                "corroborated": has_corroboration,
                "classification": cls
            }

            if cls != "NORMAL":
                beacons.append(candidate)
                self.evidence_store.create(
                    artifact_name, "PCAP_BEACON", "beacon_analysis", candidate,
                    "BehavioralAnalyzer", confidence=beacon_score, state=ev_state,
                    provenance={"destination_ip": dst_ip, "port": dst_port}
                )


        results["c2_beacons"] = sorted(beacons, key=lambda x: x["beacon_score"], reverse=True)
        return results

    def parse_procmon_csv(self) -> Dict[str, Any]:
        """
        Parses Process Monitor CSV in a streaming manner with strict limits.
        Categorizes events into canonical event types.
        """
        results: Dict[str, Any] = {
            "status": "NOT_ANALYZED",
            "dropped_files": [],
            "persistence_registry": [],
            "spawned_processes": [],
            "normalized_events": [],
            "warnings": []
        }

        if not self.procmon_path or not self.procmon_path.exists():
            return results

        artifact_name = self.procmon_path.name
        results["status"] = "OBSERVED"

        row_count = 0
        try:
            with open(self.procmon_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    row_count += 1
                    if row_count > MAX_LOG_ROWS:
                        msg = f"Reached max log row processing limit ({MAX_LOG_ROWS})."
                        self.warnings.append(msg)
                        results["warnings"].append(msg)
                        break

                    clean = {k.strip(): (v.strip() if v else "") for k, v in row.items() if k}
                    op = clean.get("Operation", "")
                    path = clean.get("Path", "")
                    proc = clean.get("Process Name", "")
                    detail = clean.get("Detail", "")
                    result = clean.get("Result", "")

                    # Categorize event
                    event_category = "OTHER"
                    if op in ("CreateFile", "WriteFile"):
                        event_category = "FILE_WRITE" if op == "WriteFile" else "FILE_CREATE"
                    elif op in ("RegSetValue", "RegCreateKey"):
                        event_category = "REGISTRY_WRITE" if op == "RegSetValue" else "REGISTRY_CREATE"
                    elif op == "Process Create":
                        event_category = "PROCESS_CREATE"

                    normalized_evt = {
                        "event_id": f"EVT-{row_count:05d}",
                        "category": event_category,
                        "process": proc,
                        "operation": op,
                        "path": path,
                        "detail": detail,
                        "result": result
                    }
                    results["normalized_events"].append(normalized_evt)

                    # 1. Dropped Files
                    if op in ("CreateFile", "WriteFile") and result == "SUCCESS":
                        lower_p = path.lower()
                        if any(ext in lower_p for ext in [".exe", ".dll", ".bat", ".vbs", ".ps1", ".scr"]):
                            drop_item = {"process": proc, "path": path, "operation": op}
                            if drop_item not in results["dropped_files"]:
                                results["dropped_files"].append(drop_item)
                                self.evidence_store.create(
                                    artifact_name, "PROCMON_FILE", "dropped_file", drop_item,
                                    "BehavioralAnalyzer", provenance={"row_index": row_count}
                                )

                    # 2. Registry Persistence
                    if op in ("RegSetValue", "RegCreateKey") and result == "SUCCESS":
                        lower_p = path.lower()
                        if any(k in lower_p for k in [
                            "currentversion\\run", "currentversion\\runonce",
                            "services\\", "winlogon", "appinit_dlls"
                        ]):
                            pers_item = {"process": proc, "key_path": path, "operation": op, "detail": detail}
                            if pers_item not in results["persistence_registry"]:
                                results["persistence_registry"].append(pers_item)
                                self.evidence_store.create(
                                    artifact_name, "PROCMON_REG", "registry_persistence", pers_item,
                                    "BehavioralAnalyzer", provenance={"row_index": row_count}
                                )

                    # 3. Spawned Processes
                    if op == "Process Create" and result == "SUCCESS":
                        proc_item = {"parent_process": proc, "command_line": detail, "path": path}
                        if proc_item not in results["spawned_processes"]:
                            results["spawned_processes"].append(proc_item)
                            self.evidence_store.create(
                                artifact_name, "PROCMON_PROC", "spawned_process", proc_item,
                                "BehavioralAnalyzer", provenance={"row_index": row_count}
                            )

        except Exception as e:
            self.errors.append(f"Error parsing Procmon CSV: {e}")

        # Trim output sizes
        results["normalized_events"] = results["normalized_events"][:100]
        results["dropped_files"] = results["dropped_files"][:30]
        results["persistence_registry"] = results["persistence_registry"][:30]
        results["spawned_processes"] = results["spawned_processes"][:20]
        return results

    def parse_regshot(self) -> Dict[str, List[str]]:
        """Parses Regshot diff file safely."""
        results: Dict[str, List[str]] = {"keys_added": [], "values_added": [], "files_added": []}
        if not self.regshot_path or not self.regshot_path.exists():
            return results

        try:
            with open(self.regshot_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            current = None
            for line in content.splitlines():
                s = line.strip()
                if "Keys added:" in s:
                    current = "keys_added"
                elif "Values added:" in s:
                    current = "values_added"
                elif "Files added:" in s:
                    current = "files_added"
                elif s.startswith("---"):
                    continue
                elif not s:
                    current = None
                elif current and s:
                    results[current].append(s)
        except Exception as e:
            self.errors.append(f"Error parsing Regshot: {e}")

        return results

    def analyze(self) -> Dict[str, Any]:
        """Executes parsing across all behavioral artifacts."""
        pcap_data = self.parse_pcap()
        procmon_data = self.parse_procmon_csv()
        regshot_data = self.parse_regshot()

        return {
            "network": pcap_data,
            "host_behavior": procmon_data,
            "regshot": regshot_data,
            "errors": self.errors,
            "warnings": self.warnings
        }
