"""
0206 - Integration Architecture: AnalyzerAdapter Contract
Defines uniform status categories and execution audits for external tool adapters:
- DETECTED: Binary/library detected on system.
- READY: Tool and required rules/scripts configured and ready for execution.
- FUNCTIONAL: Tool successfully executed and produced verified evidence.
- FAILED: Tool execution returned non-zero code or failed.
- NOT_INSTALLED: Binary or package is missing from host.
- NOT_SUPPORTED: Tool is incompatible with current OS/platform.
"""
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
import time
from pydantic import BaseModel, Field, ConfigDict

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState
from core.manifest import hash_file_streaming


import hashlib
import uuid


class AdapterStatus(str, Enum):
    NOT_INSTALLED = "NOT_INSTALLED"
    DETECTED = "DETECTED"
    READY = "READY"
    FUNCTIONAL = "FUNCTIONAL"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    CAPABILITY_DETECTION_ONLY = "CAPABILITY_DETECTION_ONLY"


class GeneratedArtifact(BaseModel):
    """External artifact provenance metadata."""
    artifact_id: str
    path: str
    sha256: str
    size: int
    source_tool: str
    tool_version: Optional[str] = None
    created_at: str

    model_config = ConfigDict(use_enum_values=True)

    @classmethod
    def from_file(cls, path: Path, source_tool: str, tool_version: Optional[str] = None) -> "GeneratedArtifact":
        p = Path(path)
        if p.exists() and p.is_file():
            hashes = hash_file_streaming(p)
            sha256 = hashes.get("sha256", hashlib.sha256(b"").hexdigest())
            size = p.stat().st_size
        else:
            sha256 = hashlib.sha256(b"").hexdigest()
            size = 0

        return cls(
            artifact_id=f"art-{uuid.uuid4().hex[:12]}",
            path=str(p.resolve()),
            sha256=sha256,
            size=size,
            source_tool=source_tool,
            tool_version=tool_version,
            created_at=datetime.now(timezone.utc).isoformat()
        )


class AdapterResult(BaseModel):
    """Execution audit record for external tool adapters."""
    adapter_name: str
    status: AdapterStatus
    started_at: str
    completed_at: str
    duration_ms: float
    exit_code: Optional[int] = None
    version: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)
    artifact_paths: List[str] = Field(default_factory=list)
    artifacts: List[GeneratedArtifact] = Field(default_factory=list)
    stdout_hash: Optional[str] = None
    stderr_hash: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

    def record_generated_artifact(self, path: Path) -> GeneratedArtifact:
        art = GeneratedArtifact.from_file(path, source_tool=self.adapter_name, tool_version=self.version)
        self.artifacts.append(art)
        if art.path not in self.artifact_paths:
            self.artifact_paths.append(art.path)
        return art

    @property
    def finished_at(self) -> str:
        return self.completed_at

    @finished_at.setter
    def finished_at(self, val: str):
        self.completed_at = val

    model_config = ConfigDict(use_enum_values=True)


class AnalyzerAdapter(ABC):
    """
    Base contract for all external tool integration adapters.
    Guarantees isolation: Core never directly imports or depends on external binaries.
    """
    name: str = "BaseAdapter"
    version: str = "1.0.0"
    tier: str = "Tier 2 (Open Source)"
    capabilities: List[str] = []

    def __init__(self, config_override: Optional[str] = None):
        self.config_override = config_override

    @abstractmethod
    def available(self) -> bool:
        """Returns True if the tool/binary/package is installed and detected."""
        pass

    @abstractmethod
    def check_functional(self) -> Tuple[AdapterStatus, str]:
        """
        Tests if the adapter is truly functional (e.g. has required rules, batch capability).
        Returns (AdapterStatus, message).
        """
        pass

    @abstractmethod
    def analyze(
        self,
        input_artifact: Path,
        evidence_store: Optional[EvidenceStore] = None,
        **kwargs
    ) -> List[EvidenceRecord]:
        """
        Executes analysis on the target artifact and returns normalized EvidenceRecords.
        If unavailable, returns a record with state=NOT_AVAILABLE. Never raises fatal errors.
        """
        pass

    def execute(
        self,
        input_artifact: Path,
        evidence_store: Optional[EvidenceStore] = None,
        **kwargs
    ) -> AdapterResult:
        """
        Executes analysis with complete timing, exit code, and audit lineage.
        """
        store = evidence_store if evidence_store is not None else EvidenceStore()
        start_iso = datetime.now(timezone.utc).isoformat()
        t0 = time.perf_counter()

        status, reason = self.check_functional()
        warnings = []
        errors = []

        if status in (AdapterStatus.NOT_INSTALLED, AdapterStatus.NOT_SUPPORTED):
            duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            warnings.append(reason)
            return AdapterResult(
                adapter_name=self.name,
                status=status,
                started_at=start_iso,
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=duration_ms,
                version=self.version,
                warnings=warnings
            )

        try:
            records = self.analyze(input_artifact, evidence_store=store, **kwargs)
            duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            eids = [r.evidence_id for r in records if r.state in (EvidenceState.OBSERVED, EvidenceState.INFERRED)]
            final_status = AdapterStatus.FUNCTIONAL if eids else status

            return AdapterResult(
                adapter_name=self.name,
                status=final_status,
                started_at=start_iso,
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=duration_ms,
                version=self.version,
                evidence_ids=eids,
                warnings=warnings,
                errors=errors
            )
        except Exception as ex:
            duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            errors.append(str(ex))
            return AdapterResult(
                adapter_name=self.name,
                status=AdapterStatus.FAILED,
                started_at=start_iso,
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=duration_ms,
                version=self.version,
                errors=errors
            )
