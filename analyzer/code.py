"""
0206 - Backward Compatibility Shim for Code Analyzer
Canonical implementation is in analyzers.code.capstone_triage.
"""
from analyzers.code.capstone_triage import (
    CodeAnalyzer,
    CAPSTONE_AVAILABLE,
)

__all__ = [
    "CodeAnalyzer",
    "CAPSTONE_AVAILABLE",
]
