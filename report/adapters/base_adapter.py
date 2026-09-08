"""
0206 - Base Report Adapter Interface
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any


class BaseReportAdapter(ABC):
    """Abstract interface for all report rendering adapters."""

    @abstractmethod
    def render(self, session_data: Dict[str, Any], output_path: Path) -> Path:
        """Renders canonical session findings into target format."""
        pass
