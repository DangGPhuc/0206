"""
0206 - Central Telemetry & Domain Schemas
Pydantic schemas unifying:
- 25 Analysis Domains
- Normalized Runtime Events (Process, Thread, File, Registry, Network, Memory, Api)
- Canonical EvidenceRecord (with parent graph and domain classification)
- Canonical Finding (distinguishing CAPABILITY vs OBSERVED_BEHAVIOR vs CONFIRMED_BEHAVIOR)
- Deterministic Assessment, Classification & Score Contribution
- Analysis Coverage Tracking
"""
from enum import Enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, ConfigDict


# =====================================================================
# Phase 2: Analysis Domain Model
# =====================================================================

class AnalysisDomain(str, Enum):
    """The 25 canonical malware analysis domains defined by 0206."""
    PE = "PE"
    LOADER = "LOADER"
    ASSEMBLY = "ASSEMBLY"
    CONTROL_FLOW = "CONTROL_FLOW"
    CODE_EXECUTION = "CODE_EXECUTION"  # Backward compatibility alias for CONTROL_FLOW
    API = "API"
    PROCESS = "PROCESS"
    THREAD = "THREAD"
    MEMORY = "MEMORY"
    FILESYSTEM = "FILESYSTEM"
    REGISTRY = "REGISTRY"
    PERSISTENCE = "PERSISTENCE"
    NETWORK = "NETWORK"
    DNS = "DNS"
    HTTP = "HTTP"
    TLS = "TLS"
    C2 = "C2"
    PACKING = "PACKING"
    OBFUSCATION = "OBFUSCATION"
    UNPACKING = "UNPACKING"
    ANTI_ANALYSIS = "ANTI_ANALYSIS"
    DOCUMENT = "DOCUMENT"
    SCRIPT = "SCRIPT"
    DOTNET = "DOTNET"
    SHELLCODE = "SHELLCODE"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"


class TransmissionMode(str, Enum):
    """Canonical transmission states for external/local AI and reputation services."""
    OFFLINE = "local"
    LOCAL_SERVICE = "local"
    REMOTE_SERVICE = "remote"


# =====================================================================
# Phase 3: Evidence Model & States
# =====================================================================

class EvidenceState(str, Enum):
    """Canonical lifecycle states of an observation or fact."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    NOT_ANALYZED = "NOT_ANALYZED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class EvidenceRecord(BaseModel):
    """
    Atomic piece of raw forensic evidence grounded directly in a source artifact.
    Preserves provenance, location, domain, and parent derivation graph.
    """
    evidence_id: str
    artifact_id: str = "sample"
    source_artifact: str = ""
    artifact_sha256: Optional[str] = None
    source_type: str = "GENERIC"  # e.g. PE_HEADER, PE_SECTION, PE_IMPORT, PCAP_DNS, PROCMON_FILE
    domain: AnalysisDomain = AnalysisDomain.PE
    additional_domains: List[AnalysisDomain] = Field(default_factory=list)
    field: str
    value: Any
    state: EvidenceState = EvidenceState.OBSERVED
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    extractor: str
    extractor_version: str = "2.0.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: Dict[str, Any] = Field(default_factory=dict)

    # Granular source location tracking
    source_record_id: Optional[str] = None
    source_line: Optional[int] = None
    source_offset: Optional[str] = None
    source_packet_number: Optional[int] = None
    source_timestamp: Optional[str] = None

    # Deduplication & Graph Derivation (Phase 14 & 23)
    parent_evidence_ids: List[str] = Field(default_factory=list)
    derivation_rule: Optional[str] = None
    derivation_version: Optional[str] = None
    fingerprint: str = ""
    duplicate_count: int = 1

    model_config = ConfigDict(use_enum_values=True, populate_by_name=True)


# =====================================================================
# Phase 12: Normalized Runtime Event Schemas
# =====================================================================

class EventType(str, Enum):
    PROCESS_CREATE = "PROCESS_CREATE"
    PROCESS_TERMINATE = "PROCESS_TERMINATE"
    THREAD_CREATE = "THREAD_CREATE"
    FILE_CREATE = "FILE_CREATE"
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"
    FILE_RENAME = "FILE_RENAME"
    REGISTRY_CREATE = "REGISTRY_CREATE"
    REGISTRY_WRITE = "REGISTRY_WRITE"
    REGISTRY_DELETE = "REGISTRY_DELETE"
    NETWORK_CONNECT = "NETWORK_CONNECT"
    DNS_QUERY = "DNS_QUERY"
    HTTP_REQUEST = "HTTP_REQUEST"
    TLS_SESSION = "TLS_SESSION"
    SERVICE_CHANGE = "SERVICE_CHANGE"
    PERSISTENCE = "PERSISTENCE"
    MEMORY_EVENT = "MEMORY_EVENT"
    API_CALL = "API_CALL"
    OTHER = "OTHER"


class NormalizedEvent(BaseModel):
    """Base normalized runtime event from dynamic/behavioral telemetry."""
    event_id: str
    event_type: EventType
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    process_name: Optional[str] = None
    pid: Optional[int] = None
    tid: Optional[int] = None
    source: str = "GENERIC"  # e.g. PROCMON, PCAP, REGSHOT, SANDBOX
    artifact_hash: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(use_enum_values=True, populate_by_name=True)


class ProcessEvent(NormalizedEvent):
    parent_pid: Optional[int] = None
    command_line: Optional[str] = None
    target_path: Optional[str] = None


class ThreadEvent(NormalizedEvent):
    target_pid: Optional[int] = None
    start_address: Optional[str] = None


class FileEvent(NormalizedEvent):
    file_path: str = ""
    operation: str = ""  # CREATE, WRITE, DELETE, RENAME
    bytes_written: Optional[int] = None


class RegistryEvent(NormalizedEvent):
    key_path: str = ""
    value_name: Optional[str] = None
    value_data: Optional[str] = None
    operation: str = ""  # CREATE, SET, DELETE


class NetworkEvent(NormalizedEvent):
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None  # TCP, UDP, DNS, HTTP, TLS
    domain_name: Optional[str] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None


class MemoryEvent(NormalizedEvent):
    target_pid: Optional[int] = None
    protection: Optional[str] = None
    allocation_size: Optional[int] = None
    base_address: Optional[str] = None


class ApiEvent(NormalizedEvent):
    api_name: str = ""
    arguments: List[str] = Field(default_factory=list)
    return_value: Optional[str] = None


# =====================================================================
# Phase 4: Finding Model
# =====================================================================

class FindingStatus(str, Enum):
    """Distinguishes static capability from observed or confirmed behavior."""
    CAPABILITY = "CAPABILITY"                      # Static import / potential capability
    OBSERVED_BEHAVIOR = "OBSERVED_BEHAVIOR"        # Directly observed artifact/action
    INFERRED_BEHAVIOR = "INFERRED_BEHAVIOR"        # Analytically inferred behavior
    CONFIRMED_BEHAVIOR = "CONFIRMED_BEHAVIOR"      # Corroborated across multiple stages/events


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingCategory(str, Enum):
    """Legacy category enum preserved for backward compatibility."""
    FILE_IDENTIFICATION = "FILE_IDENTIFICATION"
    PACKING_AND_OBFUSCATION = "PACKING_AND_OBFUSCATION"
    API_RESOLUTION = "API_RESOLUTION"
    PROCESS_INJECTION = "PROCESS_INJECTION"
    NETWORK_C2 = "NETWORK_C2"
    PERSISTENCE = "PERSISTENCE"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    DISASSEMBLY_ANOMALY = "DISASSEMBLY_ANOMALY"
    HOST_TAMPERING = "HOST_TAMPERING"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"


class Finding(BaseModel):
    """
    Tier 2: Technical inference derived strictly from one or more verified EvidenceRecords.
    Never equates a single weak heuristic with confirmed malware behavior.
    """
    finding_id: str
    domain: AnalysisDomain = AnalysisDomain.PE
    additional_domains: List[AnalysisDomain] = Field(default_factory=list)
    category: Optional[FindingCategory] = None  # Backward compatibility
    title: str
    state: EvidenceState = Field(default=EvidenceState.INFERRED, alias="evidence_level")
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    severity: FindingSeverity = FindingSeverity.MEDIUM
    details: str
    why_it_matters: str = ""
    evidence_ids: List[str] = Field(default_factory=list, alias="source_evidence_ids")
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    correlation_rule: Optional[str] = None
    recommended_validation: Optional[str] = None
    recommended_tools: List[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.CAPABILITY
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Backward compatibility properties
    @property
    def source_evidence_ids(self) -> List[str]:
        return self.evidence_ids

    @source_evidence_ids.setter
    def source_evidence_ids(self, val: List[str]):
        self.evidence_ids = val

    @property
    def evidence_level(self) -> EvidenceState:
        return self.state

    @evidence_level.setter
    def evidence_level(self, val: EvidenceState):
        self.state = val

    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)


class MitreTechniqueMapping(BaseModel):
    """Calibrated MITRE ATT&CK technique mapping with explicit confidence and evidence basis."""
    technique_id: str = Field(alias="technique")
    technique_name: str = ""
    tactic: str = ""
    status: str = "NOT_CONFIRMED"  # CONFIRMED, OBSERVED, NOT_CONFIRMED, CAPABILITY_ONLY, HEURISTIC
    confidence: float = 0.5
    basis: str = ""
    evidence_ids: List[str] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)


# =====================================================================
# Phase 4, 5 & 29: Assessment, Scoring & Coverage Models
# =====================================================================

class Classification(BaseModel):
    """Structured classification distinguishing observed vs heuristic attribution."""
    value: str
    confidence: float = 0.0
    status: str = "NOT_ESTABLISHED"  # OBSERVED, HEURISTIC, INFERRED, NOT_CONFIRMED, NOT_ANALYZED, NOT_ESTABLISHED
    basis: List[str] = Field(default_factory=list)
    hypothesis: Optional[str] = None
    hypothesis_status: Optional[str] = None


class RecommendationRecord(BaseModel):
    """Grounded operational recommendation tied directly to evidence/findings."""
    action: str
    reason: str
    priority: str = "LOW"  # HIGH, MEDIUM, LOW, INFORMATIONAL
    trigger_finding_ids: List[str] = Field(default_factory=list)

    model_config = ConfigDict(use_enum_values=True)


class ScoreContribution(BaseModel):
    """Explainable scoring contribution per finding."""
    finding_id: str
    category: str
    domain: Optional[str] = None
    base_weight: float
    confidence: float
    evidence_strength: float
    corroboration: float
    contribution: float


class CoverageStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    NOT_ANALYZED = "NOT_ANALYZED"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_CHECKED = "NOT_CHECKED"
    SKIPPED_OFFLINE = "SKIPPED_OFFLINE"


class AnalysisCoverage(BaseModel):
    """Tracks completeness across all analytical domains to prevent false impressions of full analysis."""
    domain_coverage: Dict[str, str] = Field(default_factory=dict)
    coverage_reasons: Dict[str, str] = Field(default_factory=dict)
    stages: Dict[str, Dict[str, str]] = Field(default_factory=dict)
    summary: str = ""

    model_config = ConfigDict(use_enum_values=True)


class Assessment(BaseModel):
    """Tier 3: Contextual Threat Assessment derived strictly from verified findings."""
    assessment_id: str
    title: str
    threat_level: str  # INFORMATIONAL / CLEAN, LOW, MEDIUM, HIGH, CRITICAL
    threat_score: int   # 0 - 100
    classification: str
    classification_details: Optional[Classification] = None
    score_breakdown: List[ScoreContribution] = Field(default_factory=list)
    summary: str
    key_functionality: str = ""
    purpose: Optional[str] = "NOT_ESTABLISHED"
    persistence_assessment: str = ""
    runtime_confirmation_status: str = ""
    coverage: Dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    host_iocs: List[str] = Field(default_factory=list)
    network_iocs: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    supporting_finding_ids: List[str] = Field(default_factory=list)
    evidence_graph_nodes: int = 0
    confidence: float = 0.0  # Legacy alias matching classification_confidence
    classification_confidence: float = 0.0
    analysis_confidence: float = 1.0
    ai_validation: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(use_enum_values=True, populate_by_name=True)


# =====================================================================
# Legacy Telemetry Schemas (Preserved for compatibility)
# =====================================================================

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
    classification: str = "NOT_DETECTED"
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
    classification: str = "NORMAL"


class SessionReportSchema(BaseModel):
    schema_version: str = "2.0.0"
    engine_name: str = "0206"
    engine_version: str = "2.0.0"
    manifest: Dict[str, Any]
    assessment: Assessment
    findings: List[Finding]
    evidence_records: List[EvidenceRecord]
    raw_telemetry: Dict[str, Any]
