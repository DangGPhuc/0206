"""
0206 - Backward Compatibility Shim for API Hash Database
Canonical implementation is in analyzers.static.api_hashing.
"""
from analyzers.static.api_hashing import (
    scan_binary_for_api_hashes,
    get_hash_database,
    hash_djb2,
    hash_ror13,
    hash_crc32,
    hash_fnv1a,
)

__all__ = [
    "scan_binary_for_api_hashes",
    "get_hash_database",
    "hash_djb2",
    "hash_ror13",
    "hash_crc32",
    "hash_fnv1a",
]
