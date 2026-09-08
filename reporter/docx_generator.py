"""
0206 - Backward Compatibility Shim for Legacy FOR610ReportGenerator
Delegates to the modular report adapters in the `report/` package.
"""
from pathlib import Path
from typing import Dict, Any, Optional
from report.adapters.sans_style_adapter import SANSStyleReportAdapter
from report.adapters.generic_docx_adapter import GenericDOCXReportAdapter
from report.template_validator import TemplateValidator


class FOR610ReportGenerator:
    """Legacy wrapper delegating to modern report adapters."""

    def __init__(self, template_path: Optional[Path] = None):
        self.template_path = Path(template_path) if template_path else None

    def generate(
        self,
        static_data: Dict[str, Any],
        behavioral_data: Dict[str, Any],
        ai_data: Dict[str, Any],
        output_path: Path
    ) -> Path:
        """Adapts legacy call signature into the unified session report structure."""
        from core.manifest import AnalysisManifest
        from core.findings import Assessment

        # Build session dictionary
        manifest = AnalysisManifest(
            sample_filename=static_data.get("file_info", {}).get("file_name", "Unknown"),
            sample_size_bytes=static_data.get("file_info", {}).get("file_size", 0),
            sample_hashes={"sha256": static_data.get("file_info", {}).get("sha256", "N/A")}
        )

        session_data = {
            "manifest": manifest.model_dump(),
            "assessment": ai_data if isinstance(ai_data, dict) else ai_data.model_dump(),
            "findings": [],
            "evidence_records": [],
            "raw_telemetry": {
                "static": static_data,
                "behavioral": behavioral_data,
                "code_analysis": {}
            }
        }

        # Select adapter
        if self.template_path and self.template_path.exists():
            valid, _ = TemplateValidator.validate_sans_style_template(self.template_path)
            if valid:
                adapter = SANSStyleReportAdapter(self.template_path)
                return adapter.render(session_data, output_path)

        # Default to generic adapter
        adapter = GenericDOCXReportAdapter()
        return adapter.render(session_data, output_path)
