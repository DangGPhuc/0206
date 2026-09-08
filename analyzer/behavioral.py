"""
Behavioral Artifact Ingestion Module
Ingests and normalizes dynamic malware telemetry:
- Network PCAP traces (DNS, HTTP, TLS SNI, C2 Beacons via Scapy)
- Process Monitor (Procmon) CSV logs
- Regshot Registry diffs
"""
import csv
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from scapy.all import rdpcap, DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw


class BehavioralAnalyzer:
    """Ingests behavioral traces from sandbox runs or monitoring tools."""

    def __init__(
        self, 
        pcap_path: Optional[Path] = None, 
        procmon_path: Optional[Path] = None,
        regshot_path: Optional[Path] = None
    ):
        self.pcap_path = Path(pcap_path) if pcap_path else None
        self.procmon_path = Path(procmon_path) if procmon_path else None
        self.regshot_path = Path(regshot_path) if regshot_path else None
        self.errors: List[str] = []

    def parse_pcap(self) -> Dict[str, Any]:
        """Parses network PCAP file to extract DNS, HTTP, TLS SNI, and remote connections."""
        results: Dict[str, Any] = {
            "dns_queries": [],
            "http_requests": [],
            "tls_sni": [],
            "remote_ips": [],
            "c2_beacons": [],
            "packet_count": 0
        }

        if not self.pcap_path or not self.pcap_path.exists():
            return results

        try:
            packets = rdpcap(str(self.pcap_path))
            results["packet_count"] = len(packets)
        except Exception as e:
            self.errors.append(f"Failed to read PCAP ({self.pcap_path.name}): {e}")
            return results

        dns_map: Dict[str, List[str]] = {}
        http_requests: List[Dict[str, str]] = []
        tls_sni_list: List[str] = []
        ip_connections: Dict[str, int] = {}

        # Regex for HTTP Request
        http_re = re.compile(rb'^(GET|POST|HEAD|PUT|DELETE|CONNECT)\s+([^\s]+)\s+HTTP/1\.[01]', re.IGNORECASE)
        host_re = re.compile(rb'(?i)Host:\s*([^\r\n]+)')
        ua_re = re.compile(rb'(?i)User-Agent:\s*([^\r\n]+)')

        for pkt in packets:
            # Track IP conversations
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                # Exclude local/broadcast
                if not dst_ip.startswith(("127.", "255.", "224.")):
                    ip_connections[dst_ip] = ip_connections.get(dst_ip, 0) + 1

            # DNS Query & Response
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
                            if hasattr(an, 'type') and an.type == 1:  # A record (IPv4)
                                rdata = an.rdata
                                if isinstance(rdata, str) and rdata not in dns_map[qname]:
                                    dns_map[qname].append(rdata)

            # HTTP Payload inspection
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = pkt[Raw].load
                m = http_re.match(payload)
                if m:
                    method = m.group(1).decode('ascii', errors='ignore')
                    uri = m.group(2).decode('ascii', errors='ignore')
                    host_m = host_re.search(payload)
                    ua_m = ua_re.search(payload)
                    host = host_m.group(1).decode('ascii', errors='ignore') if host_m else ""
                    user_agent = ua_m.group(1).decode('ascii', errors='ignore') if ua_m else ""

                    req_entry = {
                        "method": method,
                        "uri": uri,
                        "host": host,
                        "user_agent": user_agent,
                        "dst_ip": pkt[IP].dst if IP in pkt else ""
                    }
                    if req_entry not in http_requests:
                        http_requests.append(req_entry)

                # TLS SNI extraction (Client Hello)
                # Content type 22 (Handshake), Handshake type 1 (Client Hello)
                if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                    try:
                        # Extract server name indication extension (type 0x0000)
                        pos = payload.find(b'\x00\x00')
                        if pos != -1 and pos + 9 < len(payload):
                            ext_len = int.from_bytes(payload[pos+7:pos+9], 'big')
                            sni = payload[pos+9:pos+9+ext_len].decode('utf-8', errors='ignore')
                            if sni and "." in sni and sni not in tls_sni_list:
                                tls_sni_list.append(sni)
                    except Exception:
                        pass

        # Format DNS output
        for query, ips in dns_map.items():
            results["dns_queries"].append({
                "domain": query,
                "resolved_ips": ips
            })

        results["http_requests"] = http_requests[:25]
        results["tls_sni"] = tls_sni_list[:25]
        results["remote_ips"] = [{"ip": ip, "count": count} for ip, count in sorted(ip_connections.items(), key=lambda x: x[1], reverse=True)[:30]]

        # Heuristic C2 Beacons
        for item in results["remote_ips"]:
            if item["count"] >= 5:
                results["c2_beacons"].append({
                    "target_ip": item["ip"],
                    "packet_count": item["count"],
                    "threat": "High activity / potential persistent C2 beacon"
                })

        return results

    def parse_procmon_csv(self) -> Dict[str, Any]:
        """
        Parses Process Monitor CSV export for dropped files, registry persistence,
        and spawned child processes.
        """
        results: Dict[str, Any] = {
            "dropped_files": [],
            "persistence_registry": [],
            "spawned_processes": [],
            "suspicious_file_ops": []
        }

        if not self.procmon_path or not self.procmon_path.exists():
            return results

        try:
            with open(self.procmon_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Procmon standard column names (case insensitive matching)
                    clean_row = {k.strip(): (v.strip() if v else "") for k, v in row.items() if k}
                    
                    operation = clean_row.get("Operation", "")
                    path = clean_row.get("Path", "")
                    proc_name = clean_row.get("Process Name", "")
                    detail = clean_row.get("Detail", "")
                    result = clean_row.get("Result", "")

                    # 1. Dropped / Created Files
                    if operation in ("CreateFile", "WriteFile") and result == "SUCCESS":
                        lower_path = path.lower()
                        # Detect files dropped in Temp, AppData, Startup, or executable files
                        if any(ext in lower_path for ext in [".exe", ".dll", ".bat", ".vbs", ".ps1", ".scr"]):
                            entry = {"process": proc_name, "path": path, "operation": operation}
                            if entry not in results["dropped_files"]:
                                results["dropped_files"].append(entry)
                        elif any(folder in lower_path for folder in ["\\temp\\", "\\appdata\\", "\\startup\\", "\\programdata\\"]):
                            entry = {"process": proc_name, "path": path, "operation": operation}
                            if entry not in results["suspicious_file_ops"]:
                                results["suspicious_file_ops"].append(entry)

                    # 2. Registry Persistence
                    if operation in ("RegSetValue", "RegCreateKey") and result == "SUCCESS":
                        lower_path = path.lower()
                        if any(k in lower_path for k in [
                            "currentversion\\run", "currentversion\\runonce", 
                            "services\\", "winlogon", "appinit_dlls", "image file execution options"
                        ]):
                            entry = {
                                "process": proc_name,
                                "key_path": path,
                                "operation": operation,
                                "detail": detail
                            }
                            if entry not in results["persistence_registry"]:
                                results["persistence_registry"].append(entry)

                    # 3. Process Creation / Execution
                    if operation == "Process Create" and result == "SUCCESS":
                        entry = {
                            "parent_process": proc_name,
                            "command_line": detail,
                            "path": path
                        }
                        if entry not in results["spawned_processes"]:
                            results["spawned_processes"].append(entry)

        except Exception as e:
            self.errors.append(f"Failed to parse Procmon CSV ({self.procmon_path.name}): {e}")

        # Limit entries for report readability
        results["dropped_files"] = results["dropped_files"][:30]
        results["persistence_registry"] = results["persistence_registry"][:30]
        results["spawned_processes"] = results["spawned_processes"][:20]
        results["suspicious_file_ops"] = results["suspicious_file_ops"][:20]
        return results

    def parse_regshot(self) -> Dict[str, List[str]]:
        """Parses Regshot diff output file."""
        results: Dict[str, List[str]] = {
            "keys_added": [],
            "values_added": [],
            "files_added": []
        }
        if not self.regshot_path or not self.regshot_path.exists():
            return results

        try:
            with open(self.regshot_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            current_section = None
            for line in content.splitlines():
                line_s = line.strip()
                if "Keys added:" in line_s:
                    current_section = "keys_added"
                    continue
                elif "Values added:" in line_s:
                    current_section = "values_added"
                    continue
                elif "Files added:" in line_s:
                    current_section = "files_added"
                    continue
                elif line_s.startswith("----------------------------------"):
                    continue
                elif not line_s:
                    current_section = None
                    continue

                if current_section and line_s:
                    results[current_section].append(line_s)
        except Exception as e:
            self.errors.append(f"Failed to parse Regshot ({self.regshot_path.name}): {e}")

        for k in results:
            results[k] = results[k][:30]
        return results

    def analyze(self) -> Dict[str, Any]:
        """Executes parsing across all available behavioral artifact files."""
        pcap_data = self.parse_pcap()
        procmon_data = self.parse_procmon_csv()
        regshot_data = self.parse_regshot()

        return {
            "network": pcap_data,
            "host_behavior": procmon_data,
            "regshot": regshot_data,
            "errors": self.errors
        }
