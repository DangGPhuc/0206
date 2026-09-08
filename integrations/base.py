"""
0206 - Integration Architecture: AnalyzerAdapter Base Interface
Defines the uniform adapter contract for Tier 2 (Open Source) and Tier 3 (Proprietary) tools.
Adapters are strictly optional and emit normalized EvidenceRecord objects.
If a tool is unavailable or uninstalled, available() returns False and analysis safely continues.
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState


class AnalyzerAdapter(ABC):
    """
    Base contract for all external tool integration adapters.
    Guarantees isolation: Core never directly imports or depends on external binaries.
    """
    name: str = "BaseAdapter"
    version: str = "1.0.0"
    tier: str = "Tier 2 (Open Source)"
    capabilities: List[str] = []

    def __init__(self, config_override: Optional[str] = None):
        self.config_override = config_override

    @abstractmethod
    def available(self) -> bool:
        """Returns True if the tool/binary/package is installed and operational."""
        pass

    @abstractmethod
    def analyze(self, input_artifact: Path, evidence_store: Optional[EvidenceStore] = None) -> List[EvidenceRecord]:
        """
        Executes analysis on the target artifact and returns normalized EvidenceRecords.
        If unavailable, returns a record with state=NOT_AVAILABLE. Never raises fatal errors.
        """
        pass
