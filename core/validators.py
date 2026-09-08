"""
0206 - Validation Layer
Validates resource bounds, schema conformance, and evidence-reference grounding.
"""
from pathlib import Path
from typing import List, Dict, Any, Tuple
from core.evidence import EvidenceStore
from core.findings import Finding


class ValidationError(Exception):
    """Raised when validation constraints are violated."""
    pass


def validate_file_size(file_path: Path, max_bytes: int, file_type: str = "File") -> Tuple[bool, str]:
    """Validates that a file does not exceed resource safety limits."""
    p = Path(file_path)
    if not p.exists():
        return False, f"{file_type} not found: {file_path}"

    size = p.stat().st_size
    if size > max_bytes:
        return False, f"{file_type} exceeds safety limit: {size:,} bytes > {max_bytes:,} bytes"
    return True, "OK"


def validate_finding_evidence_grounding(
    findings: List[Finding],
    evidence_store: EvidenceStore
) -> Tuple[List[Finding], List[str]]:
    """
    Validates that every finding cites valid evidence IDs present in the evidence store.
    If a finding cites non-existent evidence, it is either flagged or downgraded.
    Returns (validated_findings, warnings).
    """
    validated = []
    warnings = []

    for f in findings:
        missing_ids = [eid for eid in f.source_evidence_ids if not evidence_store.get(eid)]
        if missing_ids:
            warnings.append(
                f"Finding '{f.finding_id}' ({f.title}) referenced non-existent evidence IDs: {missing_ids}. Evidence link pruned."
            )
            # Filter to existing evidence IDs
            clean_eids = [eid for eid in f.source_evidence_ids if evidence_store.get(eid)]
            f.source_evidence_ids = clean_eids
            if not clean_eids and f.evidence_level != "NOT_ANALYZED":
                f.confidence = min(f.confidence, 0.3)
                f.details += " [WARNING: Grounding evidence could not be verified in session evidence store]."

        validated.append(f)

    return validated, warnings
