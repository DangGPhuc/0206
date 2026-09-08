"""
API Hash Database & Signature Scanner
Precomputes and identifies common API Hashing constants in PE binaries
(djb2, ROR13, CRC32, FNV-1a, Murmur3) based on Maldev Academy Module 51 & 55.
"""
import zlib
import struct
from typing import Dict, List, Tuple, Optional

# List of critical Win32/NT APIs commonly resolved dynamically via API Hashing in malware
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
    """djb2 hash algorithm (standard seed 5381)"""
    h = 5381
    for c in s:
        h = (((h << 5) + h) + ord(c)) & 0xFFFFFFFF
    return h


def hash_ror13(s: str) -> int:
    """ROR13 hash algorithm (classic shellcode / metasploit hash)"""
    h = 0
    for c in s:
        # Rotate right 13 bits (in 32-bit space)
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def hash_crc32(s: str) -> int:
    """CRC32 standard hash"""
    return zlib.crc32(s.encode('ascii')) & 0xFFFFFFFF


def hash_fnv1a(s: str) -> int:
    """32-bit FNV-1a hash algorithm"""
    h = 0x811C9DC5
    prime = 0x01000193
    for c in s:
        h = (h ^ ord(c)) & 0xFFFFFFFF
        h = (h * prime) & 0xFFFFFFFF
    return h


def hash_murmur3(key: str, seed: int = 0) -> int:
    """32-bit MurmurHash3 algorithm"""
    data = key.encode('ascii')
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for i in range(0, nblocks * 4, 4):
        k1 = struct.unpack("<I", data[i:i+4])[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 = (h1 ^ k1) & 0xFFFFFFFF
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = ((h1 * 5) + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)
    return h1 & 0xFFFFFFFF


# Build precomputed database: {hash_val: (api_name, algo_name)}
_HASH_LOOKUP_TABLE: Dict[int, Tuple[str, str]] = {}

def get_hash_database() -> Dict[int, Tuple[str, str]]:
    """Generates or retrieves the global API hash lookup table."""
    global _HASH_LOOKUP_TABLE
    if _HASH_LOOKUP_TABLE:
        return _HASH_LOOKUP_TABLE

    for api in COMMON_TARGET_APIS:
        # Case sensitive & lowercase variations
        for variant in [api, api.lower()]:
            _HASH_LOOKUP_TABLE[hash_djb2(variant)] = (api, "djb2")
            _HASH_LOOKUP_TABLE[hash_ror13(variant)] = (api, "ROR13")
            _HASH_LOOKUP_TABLE[hash_crc32(variant)] = (api, "CRC32")
            _HASH_LOOKUP_TABLE[hash_fnv1a(variant)] = (api, "FNV-1a")
            _HASH_LOOKUP_TABLE[hash_murmur3(variant)] = (api, "Murmur3")

    return _HASH_LOOKUP_TABLE


def scan_binary_for_api_hashes(data: bytes) -> List[Dict]:
    """
    Scans raw bytes for 4-byte little-endian integers that match known API hashes.
    Returns a list of resolved APIs with offsets, values, and algorithms.
    """
    db = get_hash_database()
    matches = []
    seen = set()

    # Step in 4-byte boundaries or 1-byte slides
    # For performance and accuracy on binary code, we inspect aligned 4-byte DWORDs
    length = len(data)
    for offset in range(0, length - 4, 4):
        val = struct.unpack("<I", data[offset:offset+4])[0]
        if val in db and val not in (0, 0xFFFFFFFF):
            api_name, algo = db[val]
            key = (api_name, algo)
            if key not in seen:
                seen.add(key)
                matches.append({
                    "api": api_name,
                    "algorithm": algo,
                    "hash_hex": f"0x{val:08X}",
                    "offset_hex": f"0x{offset:08X}"
                })

    return matches
