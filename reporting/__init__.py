"""
0206 - Reporting Package
Phase 20, 21, 22: Independent, two-stage evidence-grounded reporting platform.
"""
from reporting.adapters.base import BaseReportAdapter
from reporting.adapters.json_adapter import JSONReportAdapter
from reporting.adapters.markdown_adapter import MarkdownReportAdapter
from reporting.adapters.generic_docx_adapter import GenericDOCXReportAdapter
from reporting.adapters.sans_style_adapter import SANSStyleReportAdapter
from reporting.adapters import REPORT_ADAPTER_REGISTRY
from reporting.validators.template_validator import TemplateValidator, TemplateValidationError
from reporting.basic.builder import BasicReportBuilder
from reporting.advanced.builder import AdvancedReportBuilder
from reporting.generic.template import COLOR_PALETTE, GENERIC_REPORT_SECTIONS

__all__ = [
    "BaseReportAdapter",
    "JSONReportAdapter",
    "MarkdownReportAdapter",
    "GenericDOCXReportAdapter",
    "SANSStyleReportAdapter",
    "REPORT_ADAPTER_REGISTRY",
    "TemplateValidator",
    "TemplateValidationError",
    "BasicReportBuilder",
    "AdvancedReportBuilder",
    "COLOR_PALETTE",
    "GENERIC_REPORT_SECTIONS",
]
