"""
0206 - Unified Analyzer Contract & Stage Definitions
Phase 4: Every analyzer declares:
- name
- domain(s)
- stage: BASIC_STATIC, BASIC_DYNAMIC, ADVANCED_STATIC, ADVANCED_DYNAMIC
- input requirements
- output evidence types
- dependencies
- safety level
- resource limits
"""
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Dict, Any, Optional

from core.schemas import AnalysisDomain


class AnalysisStage(str, Enum):
    """The four canonical analysis stages in 0206."""
    BASIC_STATIC = "BASIC_STATIC"
    BASIC_DYNAMIC = "BASIC_DYNAMIC"
    ADVANCED_STATIC = "ADVANCED_STATIC"
    ADVANCED_DYNAMIC = "ADVANCED_DYNAMIC"


class AnalyzerSafetyLevel(str, Enum):
    """Execution safety classification."""
    SAFE_HOST = "SAFE_HOST"                # Pure parsing, no sample code execution
    SANDBOX_ONLY = "SANDBOX_ONLY"          # Requires virtualization / isolated sandbox
    ISOLATED_NETWORK = "ISOLATED_NETWORK"  # Safe on host only with disconnected/simulated net
    OFFLINE_ONLY = "OFFLINE_ONLY"          # Zero external network lookups allowed


class AnalyzerContract(ABC):
    """
    Standard contract required of every analysis component in 0206.
    Enforces clear stage separation, input requirements, output evidence types,
    dependencies, safety level, and bounded resource limits.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable identifier of the analyzer."""
        pass

    @property
    @abstractmethod
    def domains(self) -> List[AnalysisDomain]:
        """Analysis domains covered by this analyzer."""
        pass

    @property
    @abstractmethod
    def stage(self) -> AnalysisStage:
        """Stage: BASIC_STATIC, BASIC_DYNAMIC, ADVANCED_STATIC, ADVANCED_DYNAMIC."""
        pass

    @property
    def input_requirements(self) -> List[str]:
        """Required input artifacts (e.g. ['sample_path'], ['pcap_path'])."""
        return ["sample_path"]

    @property
    def output_evidence_types(self) -> List[str]:
        """Evidence types emitted (e.g. ['PE_HEADER', 'PE_SECTION', 'PE_IMPORT'])."""
        return []

    @property
    def dependencies(self) -> List[str]:
        """System or Python dependencies required (e.g. ['pefile', 'capstone'])."""
        return []

    @property
    def safety_level(self) -> AnalyzerSafetyLevel:
        """Safety level for execution."""
        return AnalyzerSafetyLevel.SAFE_HOST

    @property
    def resource_limits(self) -> Dict[str, Any]:
        """Declared resource limits for this analyzer."""
        return {
            "max_memory_mb": 512,
            "timeout_seconds": 60,
        }

    @abstractmethod
    def analyze(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Executes analysis and emits EvidenceRecords into the session EvidenceStore.
        Returns a summary dictionary of results.
        """
        pass
