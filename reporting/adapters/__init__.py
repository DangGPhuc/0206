"""
0206 - Reporting Adapters Package
"""
from reporting.adapters.base import BaseReportAdapter
from reporting.adapters.json_adapter import JSONReportAdapter
from reporting.adapters.markdown_adapter import MarkdownReportAdapter
from reporting.adapters.generic_docx_adapter import GenericDOCXReportAdapter
from reporting.adapters.sans_style_adapter import SANSStyleReportAdapter

REPORT_ADAPTER_REGISTRY = {
    "json": JSONReportAdapter,
    "markdown": MarkdownReportAdapter,
    "generic_docx": GenericDOCXReportAdapter,
    "sans_docx": SANSStyleReportAdapter,
}

__all__ = [
    "BaseReportAdapter",
    "JSONReportAdapter",
    "MarkdownReportAdapter",
    "GenericDOCXReportAdapter",
    "SANSStyleReportAdapter",
    "REPORT_ADAPTER_REGISTRY",
]
