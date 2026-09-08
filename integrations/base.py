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
from pydantic import BaseModel, Field

from core.evidence import EvidenceStore, EvidenceRecord, EvidenceState


class AdapterStatus(str, Enum):
    DETECTED = "DETECTED"
    READY = "READY"
    FUNCTIONAL = "FUNCTIONAL"
    FAILED = "FAILED"
    NOT_INSTALLED = "NOT_INSTALLED"
    NOT_SUPPORTED = "NOT_SUPPORTED"


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
    stdout_hash: Optional[str] = None
    stderr_hash: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True


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
