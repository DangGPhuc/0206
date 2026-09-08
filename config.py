"""
0206 Configuration Module
Centralized settings, constants, resource limits, and heuristics thresholds.
Portable across Linux, macOS, and Windows with zero hardcoded absolute paths.
"""
import os
from pathlib import Path
from typing import List, Dict
from core.paths import REPO_ROOT, DEFAULT_GENERIC_DOCX_TEMPLATE, DEFAULT_GENERIC_MD_TEMPLATE

# Engine metadata
ENGINE_NAME = "0206"
ENGINE_VERSION = "2.0.0"

# Resource Safety Limits (DoS / OOM Prevention)
MAX_SAMPLE_SIZE = 100 * 1024 * 1024   # 100 MB
MAX_PCAP_SIZE = 250 * 1024 * 1024     # 250 MB
MAX_PACKETS = 50_000                  # Maximum packets processed per PCAP
MAX_STRINGS = 10_000                  # Maximum extracted strings
MAX_STRING_LENGTH = 1024              # Maximum individual string length
MAX_LOG_ROWS = 50_000                 # Maximum rows processed from Procmon CSV
MAX_REPORT_SIZE = 50 * 1024 * 1024    # 50 MB
ANALYSIS_TIMEOUT = 300                # 5 minutes default timeout

# Static Analysis Thresholds
ENTROPY_PACKED_THRESHOLD = 7.0  # Shannon entropy >= 7.0 contributes to packing score
SUSPICIOUS_SECTIONS = [
    ".upx", "upx0", "upx1", "upx2", ".aspack", ".fsg", ".mpress", 
    ".themida", ".vmp", ".enigma", ".nsp", ".pack", ".stub", ".petite"
]

# Multi-factor Beacon Detection Weights
BEACON_WEIGHTS = {
    "periodicity": 0.35,
    "destination_consistency": 0.20,
    "interval_stability": 0.25,
    "packet_size_similarity": 0.10,
    "duration": 0.10
}

# Suspicious Win32 APIs grouped by malware capability (MITRE ATT&CK aligned)
SUSPICIOUS_APIS: Dict[str, Dict[str, List[str]]] = {
    "Process Injection (T1055)": {
        "description": "Allocating, writing, or creating remote threads in foreign processes",
        "apis": [
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", 
            "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", 
            "NtQueueApcThread", "SetThreadContext", "GetThreadContext",
            "NtMapViewOfSection", "ZwMapViewOfSection", "Process32First", "Process32Next"
        ]
    },
    "Anti-Debugging & Evasion (T1497 / T1622)": {
        "description": "Checking for debuggers, sandboxes, or virtual environments",
        "apis": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugStringA", "OutputDebugStringW", "GetTickCount", "QueryPerformanceCounter",
            "FindWindowA", "FindWindowW", "GetSystemMetrics", "NtYieldExecution"
        ]
    },
    "Persistence (T1547 / T1053)": {
        "description": "Modifying autostart execution points in registry or scheduled tasks",
        "apis": [
            "RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW",
            "CreateServiceA", "CreateServiceW", "StartServiceA", "OpenSCManagerA"
        ]
    },
    "Network Communication & C2 (T1071)": {
        "description": "Establishing network sockets or HTTP connections to remote infrastructure",
        "apis": [
            "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
            "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
            "URLDownloadToFileA", "URLDownloadToFileW", "WSAStartup", "connect", "send", "recv"
        ]
    },
    "Dynamic API Resolution / Evasion (T1027)": {
        "description": "Resolving functions dynamically at runtime to hide Import Address Table",
        "apis": [
            "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
            "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"
        ]
    },
    "Cryptography & Ransomware (T1486)": {
        "description": "Cryptographic operations for payload decryption or file encryption",
        "apis": [
            "CryptAcquireContextA", "CryptGenKey", "CryptEncrypt", "CryptDecrypt",
            "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt"
        ]
    }
}

# Suspicious Strings Patterns
SUSPICIOUS_STRING_KEYWORDS = [
    "cmd.exe", "powershell.exe", "powershell", "wscript.exe", "cscript.exe",
    "bitsadmin", "certutil", "vssadmin", "wbadmin", "bcdedit",
    "CurrentVersion\\Run", "CurrentVersion\\RunOnce", "Software\\Microsoft\\Windows",
    "SeDebugPrivilege", "payload", "shellcode", "beacon", "inject", "download"
]

# Optional External Tool Executable Paths (overridable by environment variables)
EXTERNAL_TOOLS = {
    "ghidra": os.getenv("O206_GHIDRA_PATH") or os.getenv("AUTOSLEUTH_GHIDRA_PATH", "ghidra"),
    "ida": os.getenv("O206_IDA_PATH") or os.getenv("AUTOSLEUTH_IDA_PATH", "ida64"),
    "x64dbg": os.getenv("O206_X64DBG_PATH") or os.getenv("AUTOSLEUTH_X64DBG_PATH", "x64dbg"),
    "yara": os.getenv("O206_YARA_PATH") or os.getenv("AUTOSLEUTH_YARA_PATH", "yara"),
    "pesieve": os.getenv("O206_PESIEVE_PATH") or os.getenv("AUTOSLEUTH_PESIEVE_PATH", "pe-sieve")
}
