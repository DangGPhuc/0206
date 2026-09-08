"""
0206 - Canonical Evidence Data Model & Scalable Backend
Defines atomic, verifiable evidence items extracted from static and dynamic analysis.
Preserves granular source location, offsets, lines, packet numbers, derivation graph,
and content-based fingerprinting for automated deduplication and linking.
Provides pluggable backends: MemoryEvidenceBackend and SQLiteEvidenceBackend.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone
import json
import sqlite3
import hashlib
from pathlib import Path

from core.schemas import AnalysisDomain, EvidenceState, EvidenceRecord


def calculate_fingerprint(
    source_type: str,
    field: str,
    value: Any,
    artifact_sha256: Optional[str] = None
) -> str:
    """
    Computes a deterministic content fingerprint for deduplicating identical evidence facts.
    """
    if isinstance(value, (dict, list)):
        normalized_val = json.dumps(value, sort_keys=True)
    else:
        normalized_val = str(value)
    raw = f"{source_type}|{field}|{normalized_val}|{artifact_sha256 or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# =====================================================================
# Evidence Storage Backends (Abstraction, Memory, SQLite)
# =====================================================================

class EvidenceBackend(ABC):
    """Abstract storage backend interface for EvidenceStore."""

    @abstractmethod
    def add(self, record: EvidenceRecord) -> EvidenceRecord:
        pass

    @abstractmethod
    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        pass

    @abstractmethod
    def get_by_fingerprint(self, fingerprint: str) -> Optional[EvidenceRecord]:
        pass

    @abstractmethod
    def find(
        self,
        field: Optional[str] = None,
        source_type: Optional[str] = None,
        source_artifact: Optional[str] = None,
        domain: Optional[Union[str, AnalysisDomain]] = None
    ) -> List[EvidenceRecord]:
        pass

    @abstractmethod
    def all(self) -> List[EvidenceRecord]:
        pass

    @abstractmethod
    def count(self) -> int:
        pass


class MemoryEvidenceBackend(EvidenceBackend):
    """Fast in-memory backend with dictionary indexing for lightweight operations."""

    def __init__(self):
        self._by_id: Dict[str, EvidenceRecord] = {}
        self._by_fingerprint: Dict[str, str] = {}  # fingerprint -> evidence_id
        self._by_artifact: Dict[str, List[str]] = {}
        self._by_type: Dict[str, List[str]] = {}
        self._by_domain: Dict[str, List[str]] = {}

    def add(self, record: EvidenceRecord) -> EvidenceRecord:
        eid = record.evidence_id
        self._by_id[eid] = record
        if record.fingerprint:
            self._by_fingerprint[record.fingerprint] = eid

        self._by_artifact.setdefault(record.source_artifact, []).append(eid)
        self._by_type.setdefault(record.source_type, []).append(eid)
        dom_val = record.domain.value if hasattr(record.domain, "value") else str(record.domain)
        self._by_domain.setdefault(dom_val, []).append(eid)
        return record

    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        return self._by_id.get(evidence_id)

    def get_by_fingerprint(self, fingerprint: str) -> Optional[EvidenceRecord]:
        eid = self._by_fingerprint.get(fingerprint)
        return self._by_id.get(eid) if eid else None

    def find(
        self,
        field: Optional[str] = None,
        source_type: Optional[str] = None,
        source_artifact: Optional[str] = None,
        domain: Optional[Union[str, AnalysisDomain]] = None
    ) -> List[EvidenceRecord]:
        dom_str = domain.value if hasattr(domain, "value") else str(domain) if domain else None
        
        if source_artifact and source_artifact in self._by_artifact:
            candidates = [self._by_id[eid] for eid in self._by_artifact[source_artifact]]
        elif source_type and source_type in self._by_type:
            candidates = [self._by_id[eid] for eid in self._by_type[source_type]]
        elif dom_str and dom_str in self._by_domain:
            candidates = [self._by_id[eid] for eid in self._by_domain[dom_str]]
        else:
            candidates = list(self._by_id.values())

        results = []
        for r in candidates:
            if field and r.field != field:
                continue
            if source_type and r.source_type != source_type:
                continue
            if source_artifact and r.source_artifact != source_artifact:
                continue
            if dom_str:
                r_dom = r.domain.value if hasattr(r.domain, "value") else str(r.domain)
                if r_dom != dom_str and dom_str not in [
                    (d.value if hasattr(d, "value") else str(d)) for d in r.additional_domains
                ]:
                    continue
            results.append(r)
        return results

    def all(self) -> List[EvidenceRecord]:
        return list(self._by_id.values())

    def count(self) -> int:
        return len(self._by_id)


class SQLiteEvidenceBackend(EvidenceBackend):
    """Scalable, indexed SQLite backend for large-scale analysis sessions."""

    def __init__(self, db_path: str = ":memory:"):
        self._db_path = db_path
        self._conn = sqlite3.connect(self._db_path)
        self._init_schema()

    def _init_schema(self):
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                artifact_id TEXT,
                source_artifact TEXT,
                artifact_sha256 TEXT,
                source_type TEXT,
                domain TEXT,
                field_name TEXT,
                state TEXT,
                confidence REAL,
                fingerprint TEXT UNIQUE,
                record_json TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ev_artifact ON evidence(source_artifact)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ev_type ON evidence(source_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ev_field ON evidence(field_name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ev_domain ON evidence(domain)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ev_fp ON evidence(fingerprint)")
        self._conn.commit()

    def add(self, record: EvidenceRecord) -> EvidenceRecord:
        cur = self._conn.cursor()
        dom_val = record.domain.value if hasattr(record.domain, "value") else str(record.domain)
        state_val = record.state.value if hasattr(record.state, "value") else str(record.state)
        cur.execute("""
            INSERT INTO evidence (
                evidence_id, artifact_id, source_artifact, artifact_sha256, source_type, domain, field_name, state, confidence, fingerprint, record_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(evidence_id) DO UPDATE SET
                record_json = excluded.record_json,
                confidence = excluded.confidence
        """, (
            record.evidence_id,
            record.artifact_id,
            record.source_artifact,
            record.artifact_sha256,
            record.source_type,
            dom_val,
            record.field,
            state_val,
            record.confidence,
            record.fingerprint,
            record.model_dump_json()
        ))
        self._conn.commit()
        return record

    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        cur = self._conn.cursor()
        cur.execute("SELECT record_json FROM evidence WHERE evidence_id = ?", (evidence_id,))
        row = cur.fetchone()
        return EvidenceRecord(**json.loads(row[0])) if row else None

    def get_by_fingerprint(self, fingerprint: str) -> Optional[EvidenceRecord]:
        if not fingerprint:
            return None
        cur = self._conn.cursor()
        cur.execute("SELECT record_json FROM evidence WHERE fingerprint = ?", (fingerprint,))
        row = cur.fetchone()
        return EvidenceRecord(**json.loads(row[0])) if row else None

    def find(
        self,
        field: Optional[str] = None,
        source_type: Optional[str] = None,
        source_artifact: Optional[str] = None,
        domain: Optional[Union[str, AnalysisDomain]] = None
    ) -> List[EvidenceRecord]:
        query = "SELECT record_json FROM evidence WHERE 1=1"
        params = []
        if field:
            query += " AND field_name = ?"
            params.append(field)
        if source_type:
            query += " AND source_type = ?"
            params.append(source_type)
        if source_artifact:
            query += " AND source_artifact = ?"
            params.append(source_artifact)
        if domain:
            dom_val = domain.value if hasattr(domain, "value") else str(domain)
            query += " AND domain = ?"
            params.append(dom_val)

        cur = self._conn.cursor()
        cur.execute(query, tuple(params))
        return [EvidenceRecord(**json.loads(r[0])) for r in cur.fetchall()]

    def all(self) -> List[EvidenceRecord]:
        cur = self._conn.cursor()
        cur.execute("SELECT record_json FROM evidence ORDER BY rowid ASC")
        return [EvidenceRecord(**json.loads(r[0])) for r in cur.fetchall()]

    def count(self) -> int:
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM evidence")
        row = cur.fetchone()
        return row[0] if row else 0

    def close(self):
        """Closes the underlying SQLite connection."""
        if hasattr(self, "_conn") and self._conn:
            try:
                self._conn.close()
            except Exception:
                pass

    def __del__(self):
        self.close()


# =====================================================================
# Canonical EvidenceStore Interface & Queryable Derivation Graph
# =====================================================================

class EvidenceStore:
    """Unified query interface for collected evidence records with deduplication and graph derivation."""

    def __init__(self, backend: Optional[Any] = None, db_path: Optional[str] = None):
        if isinstance(backend, str):
            if backend.lower() == "sqlite":
                self._backend = SQLiteEvidenceBackend(db_path or ":memory:")
            else:
                self._backend = MemoryEvidenceBackend()
        elif backend is not None:
            self._backend = backend
        else:
            self._backend = MemoryEvidenceBackend()
        self._counter: int = 1

    def create(
        self,
        source_artifact: str,
        source_type: str,
        field: str,
        value: Any,
        extractor: str,
        confidence: float = 1.0,
        provenance: Optional[Dict[str, Any]] = None,
        state: EvidenceState = EvidenceState.OBSERVED,
        prefix: str = "E",
        artifact_sha256: Optional[str] = None,
        artifact_id: str = "sample",
        domain: Optional[Union[str, AnalysisDomain]] = None,
        additional_domains: Optional[List[AnalysisDomain]] = None,
        source_record_id: Optional[str] = None,
        source_offset: Optional[str] = None,
        source_line: Optional[int] = None,
        source_packet_number: Optional[int] = None,
        source_timestamp: Optional[str] = None,
        parent_evidence_ids: Optional[List[str]] = None,
        derivation_rule: Optional[str] = None,
        derivation_version: Optional[str] = None,
        extractor_version: str = "1.0.0",
        **kwargs
    ) -> EvidenceRecord:
        """Helper to create, deduplicate, register, and return an EvidenceRecord."""
        # Content fingerprint
        fp = calculate_fingerprint(source_type, field, value, artifact_sha256)
        existing = self._backend.get_by_fingerprint(fp)
        if existing is not None:
            existing.duplicate_count += 1
            if provenance:
                existing.provenance.setdefault("occurrences", []).append(provenance)
            self._backend.add(existing)
            return existing

        evidence_id = f"{prefix}-{self._counter:04d}"
        self._counter += 1

        prov = provenance or {}
        s_offset = source_offset or prov.get("offset") or prov.get("address")
        s_pkt = source_packet_number or prov.get("packet_index") or prov.get("packet_num")
        s_line = source_line or prov.get("row_index") or prov.get("line_num")
        s_rec_id = source_record_id or prov.get("event_id")

        # Resolve domain
        resolved_domain = AnalysisDomain.PE
        if domain:
            if isinstance(domain, AnalysisDomain):
                resolved_domain = domain
            else:
                try:
                    resolved_domain = AnalysisDomain(domain.upper())
                except Exception:
                    resolved_domain = AnalysisDomain.PE

        rec = EvidenceRecord(
            evidence_id=evidence_id,
            artifact_id=artifact_id,
            source_artifact=source_artifact,
            artifact_sha256=artifact_sha256,
            source_type=source_type,
            domain=resolved_domain,
            additional_domains=additional_domains or [],
            field=field,
            value=value,
            state=state,
            confidence=confidence,
            extractor=extractor,
            extractor_version=extractor_version,
            provenance=prov,
            source_record_id=s_rec_id,
            source_offset=str(s_offset) if s_offset is not None else None,
            source_line=s_line,
            source_packet_number=s_pkt,
            source_timestamp=source_timestamp,
            fingerprint=fp,
            parent_evidence_ids=parent_evidence_ids or [],
            derivation_rule=derivation_rule,
            derivation_version=derivation_version
        )
        self._backend.add(rec)
        return rec

    def add(self, record: EvidenceRecord) -> EvidenceRecord:
        """Adds an existing EvidenceRecord to the store."""
        if not record.fingerprint:
            record.fingerprint = calculate_fingerprint(
                record.source_type, record.field, record.value, record.artifact_sha256
            )
        self._backend.add(record)
        return record

    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Retrieves an evidence record by ID."""
        return self._backend.get(evidence_id)

    def find(
        self,
        field: Optional[str] = None,
        source_type: Optional[str] = None,
        source_artifact: Optional[str] = None,
        domain: Optional[Union[str, AnalysisDomain]] = None
    ) -> List[EvidenceRecord]:
        """Finds evidence records matching filter criteria."""
        return self._backend.find(field=field, source_type=source_type, source_artifact=source_artifact, domain=domain)

    def find_by_domain(self, domain: Union[str, AnalysisDomain]) -> List[EvidenceRecord]:
        """Finds evidence items associated with an analysis domain."""
        return self.find(domain=domain)

    # =====================================================================
    # Phase 23: Evidence Derivation Graph Queries
    # =====================================================================

    def get_parents(self, evidence_id: str) -> List[EvidenceRecord]:
        """Returns direct parent evidence records that this record was derived from."""
        rec = self.get(evidence_id)
        if not rec or not rec.parent_evidence_ids:
            return []
        parents = []
        for pid in rec.parent_evidence_ids:
            parent = self.get(pid)
            if parent:
                parents.append(parent)
        return parents

    def get_children(self, evidence_id: str) -> List[EvidenceRecord]:
        """Returns child evidence records derived directly from this record."""
        children = []
        for r in self.all():
            if evidence_id in r.parent_evidence_ids:
                children.append(r)
        return children

    def get_lineage(self, evidence_id: str) -> Dict[str, Any]:
        """Returns full recursive ancestral lineage tree for this evidence item."""
        rec = self.get(evidence_id)
        if not rec:
            return {"evidence_id": evidence_id, "status": "NOT_FOUND"}

        parents_lineage = [self.get_lineage(pid) for pid in rec.parent_evidence_ids]
        return {
            "evidence_id": rec.evidence_id,
            "source_type": rec.source_type,
            "field": rec.field,
            "domain": rec.domain,
            "derivation_rule": rec.derivation_rule,
            "parents": parents_lineage
        }

    def all(self) -> List[EvidenceRecord]:
        """Returns all records in order of creation."""
        return self._backend.all()

    def all_records(self) -> List[EvidenceRecord]:
        """Alias for all()."""
        return self.all()

    def to_dict(self) -> List[Dict[str, Any]]:
        """Serializes all records to a list of dicts."""
        return [r.model_dump() for r in self.all()]

    def to_json(self) -> str:
        """Serializes all records to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def export(self, output_path: Path) -> Path:
        """Exports evidence records to evidence.json."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        return output_path

    def hash(self) -> str:
        """Calculates deterministic SHA256 of all sorted evidence records."""
        serialized = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def __len__(self) -> int:
        return self._backend.count()
