"""
AutoSleuth-Triage Configuration Module
Centralized settings, constants, and heuristics thresholds.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict

# Paths
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_TEMPLATE_PATH = Path("/run/media/kali/New Volume/malware/Malware_Analysis_Report_Template.docx")
FALLBACK_TEMPLATE_PATH = BASE_DIR / "Malware_Analysis_Report_Template.docx"

# Static Analysis Thresholds
ENTROPY_PACKED_THRESHOLD = 7.0  # Shannon entropy >= 7.0 usually indicates packing or encryption
SUSPICIOUS_SECTIONS = [
    ".upx", "upx0", "upx1", "upx2", ".aspack", ".fsg", ".mpress", 
    ".themida", ".vmp", ".enigma", ".nsp", ".pack", ".stub"
]

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
