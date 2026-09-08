"""
0206 - Path Management & Cross-Platform Location Resolvers
Eliminates hard-coded absolute paths, providing deterministic, relative defaults.
"""
import os
from pathlib import Path

# Repository root directory
REPO_ROOT = Path(__file__).resolve().parent.parent

# Core subdirectories
CORE_DIR = REPO_ROOT / "core"
ANALYZER_DIR = REPO_ROOT / "analyzer"
AI_DIR = REPO_ROOT / "ai"
INTEGRATIONS_DIR = REPO_ROOT / "integrations"
REPORT_DIR = REPO_ROOT / "report"
GENERIC_TEMPLATES_DIR = REPORT_DIR / "generic"
TESTS_DIR = REPO_ROOT / "tests"
SCRIPTS_DIR = REPO_ROOT / "scripts"

# Default paths
DEFAULT_GENERIC_DOCX_TEMPLATE = GENERIC_TEMPLATES_DIR / "default_report.docx"
DEFAULT_GENERIC_MD_TEMPLATE = GENERIC_TEMPLATES_DIR / "default_report.md"

def get_template_path(custom_path: str = None) -> Path:
    """
    Resolves the report template path.
    1. Custom CLI path (if provided and exists)
    2. Environment variable O206_TEMPLATE_PATH
    3. Built-in generic template inside repo
    """
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p
        raise FileNotFoundError(f"Specified template file not found: {custom_path}")

    env_path = os.getenv("O206_TEMPLATE_PATH") or os.getenv("AUTOSLEUTH_TEMPLATE_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    # Default to generic built-in template
    return DEFAULT_GENERIC_DOCX_TEMPLATE


def get_output_dir(custom_dir: str = None) -> Path:
    """Resolves output directory, creating it if needed."""
    if custom_dir:
        p = Path(custom_dir)
    else:
        env_dir = os.getenv("O206_OUTPUT_DIR") or os.getenv("AUTOSLEUTH_OUTPUT_DIR")
        p = Path(env_dir) if env_dir else (REPO_ROOT / "output")
    p.mkdir(parents=True, exist_ok=True)
    return p
