"""
0206 - Backward Compatibility Shim for Static PE Analyzer
Canonical implementation is in analyzers.static.pe_analyzer.
"""
from analyzers.static.pe_analyzer import (
    PEStaticAnalyzer,
    calculate_shannon_entropy,
    extract_strings,
)

__all__ = [
    "PEStaticAnalyzer",
    "calculate_shannon_entropy",
    "extract_strings",
]
