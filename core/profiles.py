"""
0206 - Analysis Profiles Configuration
Defines analyzer scopes, resource boundaries, and tool whitelists for execution profiles:
- minimal: PE static, hashes, sections, imports, strings, Capstone triage, manifest, reports, offline AI.
- standard: minimal + PCAP, Procmon, Regshot, YARA, capa.
- full: standard + Ghidra, radare2, pe-sieve, IDA, x64dbg, WinDbg.
Tools are executed only when both enabled by profile AND available in the environment.
"""
from enum import Enum
from typing import List, Set, Dict, Any
from pydantic import BaseModel, Field


class ProfileName(str, Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    FULL = "full"


class ProfileConfig(BaseModel):
    name: ProfileName
    description: str
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
        description="Core triage: PE headers, hashes, sections, imports, Capstone triage, offline AI, manifest, and reports.",
        enable_static=True,
        enable_code=True,
        enable_behavioral=False,
        enable_ai=True,
        force_offline_ai=True,
        allowed_integrations=set(),
        report_formats=["json", "md", "docx"]
    ),
    ProfileName.STANDARD: ProfileConfig(
        name=ProfileName.STANDARD,
        description="Standard triage: Minimal profile + PCAP, Procmon, Regshot, YARA, and capa when available.",
        enable_static=True,
        enable_code=True,
        enable_behavioral=True,
        enable_ai=True,
        force_offline_ai=False,
        allowed_integrations={"YARA", "capa"},
        report_formats=["json", "md", "docx"]
    ),
    ProfileName.FULL: ProfileConfig(
        name=ProfileName.FULL,
        description="Full deep triage: Standard profile + Ghidra, radare2, pe-sieve, IDA Pro, x64dbg, WinDbg when available.",
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
