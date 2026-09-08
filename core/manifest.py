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
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def hash_file_streaming(file_path: Path, chunk_size: int = 65536) -> Dict[str, str]:
    """
    Computes MD5, SHA1, and SHA256 hashes in streaming chunks.
    Does NOT load large files into RAM.
    """
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return {"md5": "N/A", "sha1": "N/A", "sha256": "N/A"}

    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
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


class AnalysisManifest(BaseModel):
    """
    Comprehensive record of an analysis run for auditability and reproducibility.
    """
    schema_version: str = "2.0.0"
    case_id: str = Field(default_factory=lambda: f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}")
    start_time_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time_utc: Optional[str] = None
    
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

    # Operational Modes
    ai_mode: str = "offline"
    privacy_mode: str = "strict"
    profile: str = "standard"
    template_name: Optional[str] = None
    template_sha256: Optional[str] = None
    adapter_versions: Dict[str, str] = Field(default_factory=dict)

    # Output Lineage & Deliverable Hashes
    output_lineage: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    # Pipeline status
    analyzers_enabled: List[str] = Field(default_factory=list)
    analyzers_skipped: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    cli_arguments: Dict[str, Any] = Field(default_factory=dict)

    def complete(self):
        """Marks the end time of the analysis."""
        self.end_time_utc = datetime.now(timezone.utc).isoformat()

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
        """Hashes and records a generated output artifact for lineage auditing."""
        p = Path(file_path)
        if p.exists():
            hashes = hash_file_streaming(p)
            self.output_lineage[name] = {
                "filename": p.name,
                "size_bytes": p.stat().st_size,
                "sha256": hashes.get("sha256", "N/A"),
                "hashes": hashes
            }

    def export_json(self, output_path: Path):
        """Exports manifest to JSON file."""
        if not self.end_time_utc:
            self.complete()
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(self.model_dump(), indent=2))

