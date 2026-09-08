"""
0206 - Win32 API Hashing Algorithms & Precomputed Constants Database
Identifies dynamic API resolution constants (djb2, ROR13, CRC32, FNV-1a, Murmur3)
frequently embedded in binary payloads to bypass static Import Address Table (IAT) inspection.
"""
import zlib
import struct
from typing import Dict, List, Tuple, Optional, Any

# Win32/NT APIs commonly resolved dynamically via API Hashing in malware
COMMON_TARGET_APIS = [
    # Process Injection & Memory
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
    "OpenProcess", "CreateProcessA", "CreateProcessW", "TerminateProcess",
    "VirtualFree", "VirtualFreeEx", "MapViewOfFile", "CreateFileMappingA",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
    "NtReadVirtualMemory", "NtMapViewOfSection", "NtUnmapViewOfSection",
    
    # Evasion & Anti-Debug
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "NtSetInformationThread", "OutputDebugStringA", "OutputDebugStringW",
    
    # Module & Symbol Resolution
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress",
    "GetModuleHandleA", "GetModuleHandleW", "LdrLoadDll", "LdrGetProcedureAddress",
    
    # Process & Thread Enumeration
    "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "Process32FirstW", "Process32NextW",
    "Thread32First", "Thread32Next", "OpenThread", "SuspendThread", "ResumeThread",
    
    # Persistence & Registry
    "RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA", "RegSetValueExA", "RegSetValueExW",
    "CreateServiceA", "CreateServiceW", "StartServiceA", "OpenSCManagerA",
    
    # Networking & C2
    "WSAStartup", "socket", "connect", "send", "recv", "closesocket",
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA",
    "InternetReadFile", "URLDownloadToFileA", "URLDownloadToFileW",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest"
]


def hash_djb2(s: str) -> int:
    """djb2 hash algorithm (standard seed 5381)."""
    h = 5381
    for c in s:
        h = (((h << 5) + h) + ord(c)) & 0xFFFFFFFF
    return h


def hash_ror13(s: str) -> int:
    """ROR13 hash algorithm (classic shellcode / metasploit hash)."""
    h = 0
    for c in s:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def hash_crc32(s: str) -> int:
    """Standard CRC32 IEEE 802.3."""
    return zlib.crc32(s.encode("ascii", errors="ignore")) & 0xFFFFFFFF


def hash_fnv1a(s: str) -> int:
    """FNV-1a 32-bit hash."""
    h = 0x811C9DC5
    for c in s:
        h = (h ^ ord(c)) & 0xFFFFFFFF
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def get_hash_database() -> Dict[int, Tuple[str, str]]:
    """
    Generates dictionary of {hash_value: (api_name, algorithm_name)}.
    """
    db: Dict[int, Tuple[str, str]] = {}
    for api in COMMON_TARGET_APIS:
        db[hash_djb2(api)] = (api, "djb2")
        db[hash_ror13(api)] = (api, "ror13")
        db[hash_crc32(api)] = (api, "crc32")
        db[hash_fnv1a(api)] = (api, "fnv1a")
    return db


def scan_binary_for_api_hashes(binary_data: bytes, hash_db: Optional[Dict[int, Tuple[str, str]]] = None) -> List[Dict[str, Any]]:
    """
    Scans raw PE bytes for 4-byte little-endian / big-endian constants matching API hash DB.
    Returns list of matched APIs with offsets and algorithms.
    """
    if hash_db is None:
        hash_db = get_hash_database()

    matches = []
    seen = set()

    for i in range(0, len(binary_data) - 4, 4):
        val_le = struct.unpack_from("<I", binary_data, i)[0]
        if val_le in hash_db:
            api, algo = hash_db[val_le]
            key = (api, algo)
            if key not in seen:
                seen.add(key)
                matches.append({
                    "offset": hex(i),
                    "hash_value": hex(val_le),
                    "api": api,
                    "algorithm": algo,
                    "endianness": "little"
                })

        val_be = struct.unpack_from(">I", binary_data, i)[0]
        if val_be in hash_db:
            api, algo = hash_db[val_be]
            key = (api, algo)
            if key not in seen:
                seen.add(key)
                matches.append({
                    "offset": hex(i),
                    "hash_value": hex(val_be),
                    "api": api,
                    "algorithm": algo,
                    "endianness": "big"
                })

    return matches
