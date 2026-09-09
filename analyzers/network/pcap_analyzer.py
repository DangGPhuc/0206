"""
0206 - Streaming Network Traffic & Multi-Factor Beacon Analyzer
Processes PCAP traces in memory-bounded streaming chunks without unbounded rdpcap().
Calibrated C2 beaconing terminology:
- OBSERVED_PERIODIC_TRAFFIC
- SUSPECTED_BEACONING
- LIKELY_C2_BEACON
- CONFIRMED_C2
Enforces global connection and packet limits.
"""
import os
import re
import statistics
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

from config import (
    MAX_PCAP_SIZE, MAX_PACKETS, MAX_TRACKED_CONNECTIONS, MAX_TIMESTAMPS_PER_CONNECTION
)
from core.schemas import AnalysisDomain, EvidenceState
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming

import warnings
warnings.filterwarnings("ignore", module="scapy.*")
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except Exception:
    pass

try:
    from scapy.utils import PcapReader
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns import DNS
    from scapy.packet import Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


BEACON_WEIGHTS = {
    "periodicity": 0.35,
    "destination_consistency": 0.20,
    "interval_stability": 0.20,
    "packet_size_similarity": 0.15,
    "duration": 0.10
}


class NetworkAnalyzer:
    """Performs streaming PCAP telemetry extraction and multi-factor C2 beaconing analysis."""

    def __init__(self, pcap_path: Path, evidence_store: Optional[EvidenceStore] = None):
        self.pcap_path = Path(pcap_path) if pcap_path else None
        self.evidence_store = evidence_store if evidence_store is not None else EvidenceStore()
        self.errors: List[str] = []

    def analyze(self) -> Dict[str, Any]:
        """Runs memory-bounded streaming PCAP processing."""
        if not self.pcap_path or not self.pcap_path.exists():
            return {"status": "SKIPPED", "message": "No PCAP file provided."}

        pcap_size = self.pcap_path.stat().st_size
        if pcap_size > MAX_PCAP_SIZE:
            self.errors.append(f"PCAP exceeds max size limit ({pcap_size} > {MAX_PCAP_SIZE} bytes).")
            return {"status": "ERROR", "message": "PCAP size exceeded."}

        if not SCAPY_AVAILABLE:
            return {"status": "NOT_AVAILABLE", "message": "Scapy library not installed."}

        hashes = hash_file_streaming(self.pcap_path)
        sha256 = hashes.get("sha256", "UNKNOWN")
        artifact_name = self.pcap_path.name

        conversations: Dict[Tuple[str, int], Dict[str, Any]] = {}
        dns_map: Dict[str, List[str]] = {}
        http_requests: List[Dict[str, Any]] = []
        tls_sni_list: List[str] = []
        packet_idx = 0

        http_re = re.compile(rb'^(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+([^\s]+)\s+HTTP/1\.[01]', re.IGNORECASE)
        host_re = re.compile(rb'(?:Host:\s*)([^\r\n]+)', re.IGNORECASE)
        ua_re = re.compile(rb'(?:User-Agent:\s*)([^\r\n]+)', re.IGNORECASE)

        try:
            with PcapReader(str(self.pcap_path)) as pcap_reader:
                for pkt in pcap_reader:
                    packet_idx += 1
                    if packet_idx > MAX_PACKETS:
                        self.errors.append(f"Reached MAX_PACKETS limit ({MAX_PACKETS}). Truncated streaming read.")
                        break

                    pkt_time = float(pkt.time) if hasattr(pkt, 'time') else 0.0

                    # Flow Tracking (bounded by MAX_TRACKED_CONNECTIONS)
                    if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                        ip_layer = pkt[IP]
                        dst_ip = ip_layer.dst
                        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
                        key = (dst_ip, dst_port)

                        if key not in conversations and len(conversations) < MAX_TRACKED_CONNECTIONS:
                            conversations[key] = {
                                "timestamps": [],
                                "payload_sizes": [],
                                "protocol": "TCP" if pkt.haslayer(TCP) else "UDP"
                            }

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

                    # HTTP Inspection
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
                                    "NetworkAnalyzer", artifact_sha256=sha256, domain=AnalysisDomain.HTTP,
                                    provenance={"packet_index": packet_idx}
                                )

                        # TLS SNI Extraction
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
                                            "NetworkAnalyzer", artifact_sha256=sha256, domain=AnalysisDomain.TLS,
                                            provenance={"packet_index": packet_idx}
                                        )
                            except Exception:
                                pass

        except Exception as e:
            self.errors.append(f"Error reading PCAP streaming packets: {e}")

        # Store DNS Evidence
        for domain_name, resolved_ips in dns_map.items():
            self.evidence_store.create(
                artifact_name, "PCAP_DNS", "dns_query", {
                    "domain": domain_name,
                    "resolved_ips": resolved_ips
                }, "NetworkAnalyzer", artifact_sha256=sha256, domain=AnalysisDomain.DNS
            )

        # Multi-factor Composite Beacon Detection
        total_packets = max(1, packet_idx)
        beacons = []

        for (dst_ip, dst_port), data in conversations.items():
            tstamps = sorted(data["timestamps"])
            pkt_count = len(tstamps)

            if pkt_count < 4:
                continue

            intervals = [tstamps[i+1] - tstamps[i] for i in range(len(tstamps)-1)]
            duration = tstamps[-1] - tstamps[0]
            avg_int = statistics.mean(intervals)
            median_int = statistics.median(intervals)
            std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
            jitter_ratio = (std_dev / avg_int) if avg_int > 0 else 1.0

            periodicity_score = max(0.0, min(1.0, 1.0 - (jitter_ratio / 0.8)))
            destination_consistency_score = min(1.0, (pkt_count / total_packets) * 2.5)
            int_diff = abs(avg_int - median_int)
            stability_score = max(0.0, min(1.0, 1.0 - (int_diff / (avg_int + 0.001))))

            sizes = data["payload_sizes"]
            size_std = statistics.stdev(sizes) if len(sizes) > 1 else 0.0
            size_mean = statistics.mean(sizes) if sizes else 0.0
            size_score = max(0.0, min(1.0, 1.0 - (size_std / (size_mean + 1.0))))

            duration_score = min(1.0, duration / 60.0)

            beacon_score = (
                periodicity_score * BEACON_WEIGHTS["periodicity"] +
                destination_consistency_score * BEACON_WEIGHTS["destination_consistency"] +
                stability_score * BEACON_WEIGHTS["interval_stability"] +
                size_score * BEACON_WEIGHTS["packet_size_similarity"] +
                duration_score * BEACON_WEIGHTS["duration"]
            )
            beacon_score = round(beacon_score, 4)

            # Phase 15 & 8 Calibrated Terminology
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
                ev_state = EvidenceState.INFERRED
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
                "destination_consistency_score": round(destination_consistency_score, 3),
                "interval_stability_score": round(stability_score, 3),
                "packet_size_similarity_score": round(size_score, 3),
                "duration_score": round(duration_score, 3),
                "beacon_score": beacon_score,
                "classification": cls
            }
            beacons.append(candidate)

            if cls in ("OBSERVED_PERIODIC_TRAFFIC", "SUSPECTED_BEACONING", "LIKELY_C2_BEACON", "CONFIRMED_C2"):
                self.evidence_store.create(
                    artifact_name, "NETWORK_TELEMETRY", "beacon_analysis", candidate,
                    "NetworkAnalyzer", artifact_sha256=sha256, domain=AnalysisDomain.C2,
                    state=ev_state, confidence=beacon_score,
                    provenance={"destination": f"{dst_ip}:{dst_port}", "score": beacon_score}
                )

        dns_query_list = [{"domain": d, "resolved_ips": ips} for d, ips in dns_map.items()]

        return {
            "status": "OBSERVED" if packet_idx > 0 else "NOT_ANALYZED",
            "packet_count": packet_idx,
            "dns_queries": dns_query_list,
            "dns_map": dns_map,
            "http_requests": http_requests,
            "tls_sni": tls_sni_list,
            "beacon_candidates": beacons,
            "c2_beacons": beacons,
            "errors": self.errors
        }
