"""
0206 - Analysis Manifest & Reproducibility Module
Tracks session metadata, environment specs, and streaming artifact hashes.
Guarantees deterministic, reproducible analysis records without storing secrets.
"""
import sys
import uuid
import platform
import hashlib
import json
import importlib.metadata
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from core.atomic_io import atomic_write_text


def hash_file_streaming(file_path: Path, chunk_size: int = 65536) -> Dict[str, str]:
    """
    Computes MD5, SHA1, and SHA256 hashes in streaming chunks.
    Does NOT load large files into RAM.
    """
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return {"md5": "N/A", "sha1": "N/A", "sha256": "N/A"}

    h_md5 = hashlib.md5(usedforsecurity=False)
    h_sha1 = hashlib.sha1(usedforsecurity=False)
    h_sha256 = hashlib.sha256()

    with open(p, "rb") as f:
        while chunk := f.read(chunk_size):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)

    return {
        "md5": h_md5.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "sha256": h_sha256.hexdigest()
    }


def collect_dependency_versions() -> Dict[str, str]:
    """Inspects installed Python package versions for core dependencies."""
    packages = ["pefile", "scapy", "capstone", "pydantic", "jinja2", "python-docx", "rich", "dpkt", "yara-python", "openai", "cryptography"]
    versions: Dict[str, str] = {}
    for pkg in packages:
        try:
            versions[pkg] = importlib.metadata.version(pkg)
        except Exception:
            versions[pkg] = "not installed"
    return versions


class AnalysisManifest(BaseModel):
    """
    Comprehensive record of an analysis run for auditability and reproducibility.
    Mathematically consistent: external integrity verified via companion .sha256.
    """
    schema_version: str = "2.0.0"
    case_id: str = Field(default_factory=lambda: f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}")
    start_time_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time_utc: Optional[str] = None
    duration_ms: Optional[float] = None
    timings: Dict[str, float] = Field(default_factory=dict)
    
    # Target Sample Info
    sample_filename: Optional[str] = None
    sample_size_bytes: Optional[int] = None
    sample_hashes: Dict[str, str] = Field(default_factory=dict)

    # Secondary Artifacts Info (PCAP, Procmon, Regshot)
    artifacts: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    # Runtime Environment
    engine_name: str = "0206"
    engine_version: str = "2.0.0"
    python_version: str = Field(default_factory=lambda: f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    platform_system: str = Field(default_factory=platform.system)
    platform_release: str = Field(default_factory=platform.release)
    platform_machine: str = Field(default_factory=platform.machine)
    dependency_versions: Dict[str, str] = Field(default_factory=collect_dependency_versions)
    external_tool_versions: Dict[str, str] = Field(default_factory=dict)

    # Operational Modes
    ai_mode: str = "offline"
    ai_metadata: Dict[str, Any] = Field(default_factory=dict)
    privacy_mode: str = "strict"
    profile: str = "standard"
    sandbox_provider: Optional[str] = "NOT_USED"
    network_mode: Optional[str] = "UNVERIFIED"
    snapshot_identifier: Optional[str] = None
    configuration_hash: Optional[str] = None
    reputation: Dict[str, Any] = Field(default_factory=dict)
    template_name: Optional[str] = None
    template_sha256: Optional[str] = None
    adapter_versions: Dict[str, str] = Field(default_factory=dict)
    adapter_execution_metadata: List[Dict[str, Any]] = Field(default_factory=list)

    # Resource policy bounds applied during this session (Phase 12 & 21)
    resource_limits: Dict[str, Any] = Field(default_factory=dict)

    # Output Lineage & Deliverable Hashes (excludes self-referential manifest hash)
    output_lineage: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    # Pipeline status
    analyzers_enabled: List[str] = Field(default_factory=list)
    analyzers_skipped: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    cli_arguments: Dict[str, Any] = Field(default_factory=dict)

    def complete(self):
        """Marks the end time and duration of the analysis."""
        self.end_time_utc = datetime.now(timezone.utc).isoformat()
        try:
            t_start = datetime.fromisoformat(self.start_time_utc)
            t_end = datetime.fromisoformat(self.end_time_utc)
            self.duration_ms = round((t_end - t_start).total_seconds() * 1000.0, 2)
        except Exception:
            pass

    def record_timing(self, stage: str, duration_ms: float):
        """Records execution timing for a specific stage or analyzer."""
        self.timings[stage] = round(duration_ms, 2)

    def record_adapter_result(self, result: Any):
        """Records AdapterResult into execution audit lineage."""
        if hasattr(result, "model_dump"):
            self.adapter_execution_metadata.append(result.model_dump())
        elif isinstance(result, dict):
            self.adapter_execution_metadata.append(result)

    def record_artifact(self, name: str, file_path: Path):
        """Hashes and records an input artifact."""
        p = Path(file_path)
        if p.exists():
            hashes = hash_file_streaming(p)
            self.artifacts[name] = {
                "filename": p.name,
                "size_bytes": p.stat().st_size,
                "hashes": hashes
            }

    def record_output_artifact(self, name: str, file_path: Path):
        """
        Hashes and records a generated output artifact for lineage auditing.
        Strictly excludes self-referential manifest files to prevent hash poisoning.
        """
        p = Path(file_path)
        if p.name in ("analysis_manifest.json", "analysis_manifest.sha256"):
            return

        if p.exists():
            hashes = hash_file_streaming(p)
            self.output_lineage[name] = {
                "filename": p.name,
                "size_bytes": p.stat().st_size,
                "sha256": hashes.get("sha256", "N/A"),
                "hashes": hashes
            }

    def export_json(self, output_path: Path) -> Path:
        """
        Exports manifest to JSON file and generates a companion external .sha256 file
        for mathematically consistent integrity verification.
        Returns the path to the companion sha256 file.
        """
        if not self.end_time_utc:
            self.complete()

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        dumped = self.model_dump()
        if self.privacy_mode in ("strict", "standard"):
            from core.privacy import PrivacyRedactor
            dumped = PrivacyRedactor(mode=self.privacy_mode).redact(dumped)
        content = json.dumps(dumped, indent=2)
        atomic_write_text(output_path, content)

        # Generate external companion sha256 atomically
        sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        sha256_path = output_path.parent / "analysis_manifest.sha256"
        atomic_write_text(sha256_path, f"{sha256_hash}  {output_path.name}\n")
        return sha256_path


