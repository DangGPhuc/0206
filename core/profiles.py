"""
0206 - Analysis Profiles Configuration
Phase 27: Defines analyzer scopes, resource boundaries, and tool whitelists for execution profiles:
- minimal: core metadata and hashes only.
- basic: minimal + static, code triage, basic behavioral artifacts, reputation.
- standard: basic + network streaming, Procmon, Regshot, YARA, capa.
- advanced: standard + advanced code analysis, Ghidra, radare2, pe-sieve, FLOSS.
- full: everything available across all tiers.
Tools are executed only when both enabled by profile AND available in the environment.
Missing tools are SKIPPED, never failed.
"""
from enum import Enum
from typing import List, Set, Dict, Any
from pydantic import BaseModel, Field


class ProfileName(str, Enum):
    MINIMAL = "minimal"
    BASIC = "basic"
    STANDARD = "standard"
    ADVANCED = "advanced"
    FULL = "full"


class ProfileConfig(BaseModel):
    name: ProfileName
    description: str
    enable_reputation: bool = True
    enable_static: bool = True
    enable_code: bool = True
    enable_behavioral: bool = True
    enable_ai: bool = True
    force_offline_ai: bool = False
    allowed_integrations: Set[str] = Field(default_factory=set)
    report_formats: List[str] = Field(default_factory=lambda: ["json", "md", "docx"])


PROFILES: Dict[ProfileName, ProfileConfig] = {
    ProfileName.MINIMAL: ProfileConfig(
        name=ProfileName.MINIMAL,
        description="Minimal: core metadata and hashes only.",
        enable_reputation=False,
        enable_static=True,
        enable_code=False,
        enable_behavioral=False,
        enable_ai=True,
        force_offline_ai=True,
        allowed_integrations=set(),
        report_formats=["json", "md", "docx"]
    ),
    ProfileName.BASIC: ProfileConfig(
        name=ProfileName.BASIC,
        description="Basic: reputation, static PE, code triage, basic behavioral artifacts.",
        enable_reputation=True,
        enable_static=True,
        enable_code=True,
        enable_behavioral=True,
        enable_ai=True,
        force_offline_ai=True,
        allowed_integrations=set(),
        report_formats=["json", "md", "docx"]
    ),
    ProfileName.STANDARD: ProfileConfig(
        name=ProfileName.STANDARD,
        description="Standard: Basic profile + network PCAP streaming, Procmon, Regshot, YARA, and capa when available.",
        enable_reputation=True,
        enable_static=True,
        enable_code=True,
        enable_behavioral=True,
        enable_ai=True,
        force_offline_ai=False,
        allowed_integrations={"YARA", "capa"},
        report_formats=["json", "md", "docx"]
    ),
    ProfileName.ADVANCED: ProfileConfig(
        name=ProfileName.ADVANCED,
        description="Advanced: Standard profile + advanced code analysis, Ghidra, radare2, pe-sieve, FLOSS.",
        enable_reputation=True,
        enable_static=True,
        enable_code=True,
        enable_behavioral=True,
        enable_ai=True,
        force_offline_ai=False,
        allowed_integrations={"YARA", "capa", "Ghidra", "radare2", "pe-sieve", "FLOSS"},
        report_formats=["json", "md", "docx"]
    ),
    ProfileName.FULL: ProfileConfig(
        name=ProfileName.FULL,
        description="Full: everything available across all open-source and optional proprietary tools.",
        enable_reputation=True,
        enable_static=True,
        enable_code=True,
        enable_behavioral=True,
        enable_ai=True,
        force_offline_ai=False,
        allowed_integrations={"YARA", "capa", "Ghidra", "radare2", "pe-sieve", "FLOSS", "IDA Pro", "x64dbg", "WinDbg"},
        report_formats=["json", "md", "docx"]
    )
}


def get_profile(name: str) -> ProfileConfig:
    """Retrieves profile configuration by name, defaulting to 'standard'."""
    try:
        p_enum = ProfileName(name.lower().strip())
        return PROFILES[p_enum]
    except Exception:
        return PROFILES[ProfileName.STANDARD]
