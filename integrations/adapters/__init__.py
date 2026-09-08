"""
0206 Tool Integration Adapters Registry
"""
from typing import Dict, Type
from integrations.base import AnalyzerAdapter
from integrations.adapters.yara_adapter import YaraAdapter
from integrations.adapters.capa_adapter import CapaAdapter
from integrations.adapters.ghidra_adapter import GhidraAdapter
from integrations.adapters.radare2_adapter import Radare2Adapter
from integrations.adapters.pesieve_adapter import PeSieveAdapter
from integrations.adapters.floss_adapter import FlossAdapter
from integrations.adapters.ida_adapter import IdaProAdapter
from integrations.adapters.x64dbg_adapter import X64DbgAdapter
from integrations.adapters.windbg_adapter import WinDbgAdapter

ADAPTER_REGISTRY: Dict[str, Type[AnalyzerAdapter]] = {
    "YARA": YaraAdapter,
    "capa": CapaAdapter,
    "Ghidra": GhidraAdapter,
    "radare2": Radare2Adapter,
    "pe-sieve": PeSieveAdapter,
    "FLOSS": FlossAdapter,
    "IDA Pro": IdaProAdapter,
    "x64dbg": X64DbgAdapter,
    "WinDbg": WinDbgAdapter,
}

__all__ = [
    "AnalyzerAdapter",
    "ADAPTER_REGISTRY",
    "YaraAdapter",
    "CapaAdapter",
    "GhidraAdapter",
    "Radare2Adapter",
    "PeSieveAdapter",
    "FlossAdapter",
    "IdaProAdapter",
    "X64DbgAdapter",
    "WinDbgAdapter",
]
