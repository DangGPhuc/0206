"""
0206 - Central Telemetry Schemas
Pydantic schemas unifying outputs from analyzers, findings, and reporters.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from core.evidence import EvidenceRecord
from core.findings import Finding, Assessment


class FileMetadataSchema(BaseModel):
    file_name: str
    file_size_bytes: int
    md5: str
    sha1: str
    sha256: str
    imphash: Optional[str] = "N/A"
    overall_entropy: float = 0.0
    is_pe: bool = False
    is_signed: bool = False
    architecture: str = "Unknown"
    subsystem: str = "Unknown"
    entry_point: str = "0x0"
    image_base: str = "0x0"
    compile_time: str = "N/A"


class SectionInfoSchema(BaseModel):
    name: str
    virtual_address: str
    virtual_size: int
    raw_size: int
    entropy: float
    permissions: str
    is_rwx: bool = False
    md5: str


class PackerAssessmentSchema(BaseModel):
    classification: str = "NOT_DETECTED"  # NOT_DETECTED, POSSIBLE_PACKING, LIKELY_PACKED, UNPACKING_REQUIRED
    score: int = 0
    confidence: float = 0.5
    indicators: List[str] = Field(default_factory=list)
    caveats: List[str] = Field(default_factory=list)


class BeaconCandidateSchema(BaseModel):
    destination_ip: str
    destination_port: int = 80
    packet_count: int = 0
    duration_seconds: float = 0.0
    avg_interval: float = 0.0
    median_interval: float = 0.0
    std_dev_interval: float = 0.0
    jitter_ratio: float = 0.0
    min_interval: float = 0.0
    max_interval: float = 0.0
    periodicity_score: float = 0.0
    destination_consistency_score: float = 0.0
    interval_stability_score: float = 0.0
    packet_size_similarity_score: float = 0.0
    duration_score: float = 0.0
    beacon_score: float = 0.0
    classification: str = "NORMAL"  # NORMAL, SUSPICIOUS, LIKELY_BEACON, HIGH_CONFIDENCE_BEACON


class SessionReportSchema(BaseModel):
    schema_version: str = "2.0.0"
    engine_name: str = "0206"
    engine_version: str = "2.0.0"
    manifest: Dict[str, Any]
    assessment: Assessment
    findings: List[Finding]
    evidence_records: List[EvidenceRecord]
    raw_telemetry: Dict[str, Any]
