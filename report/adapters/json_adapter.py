"""
0206 - Canonical JSON Report Adapter
Exports complete structured evidence, findings, and assessment into standard JSON.
"""
import json
from pathlib import Path
from typing import Dict, Any
from report.adapters.base_adapter import BaseReportAdapter


class JSONReportAdapter(BaseReportAdapter):
    """Serializes canonical malware triage session to standard JSON."""

    def render(self, session_data: Dict[str, Any], output_path: Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2)

        return output_path
