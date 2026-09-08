"""
0206 - Base Report Adapter Interface
Phase 20 & 21: Defines common report generation interface.
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any


class BaseReportAdapter(ABC):
    """Abstract base class for all 0206 report rendering adapters."""

    @abstractmethod
    def render(self, session_data: Dict[str, Any], output_path: Path) -> Path:
        """
        Renders session data into the destination file format.
        Returns the written Path.
        """
        pass
