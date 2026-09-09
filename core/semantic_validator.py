"""
0206 - Case Semantic Validator
Comprehensive post-triage validation engine verifying:
- Coverage consistency across coverage.json, assessment.json, CLI, reports
- Canonical evidence count consistency
- Finding evidence references and grounding integrity
- Classification consistency (clean baseline != generic malware, confidence != 1.0 on unknown)
- Reputation semantics (offline != completed, 0/0 != clean)
- NOT_ANALYZED semantics (unexecuted domains must not claim negative detection)
- Score / finding consistency
- Privacy-safe output (no leaked analyst paths, usernames, API keys)
- Manifest integrity and cryptographic companion hash verification
"""
import re
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from pydantic import BaseModel, Field


class ValidationIssue(BaseModel):
    rule: str
    severity: str  # FAIL, WARNING, PASS
    message: str
    artifact: str = ""


class SemanticValidationResult(BaseModel):
    case_dir: str
    status: str  # PASS, WARNING, FAIL
    passed_checks: int = 0
    warning_checks: int = 0
    failed_checks: int = 0
    issues: List[ValidationIssue] = Field(default_factory=list)

    def is_pass(self) -> bool:
        return self.status == "PASS"


class CaseSemanticValidator:
    """
    Validates the semantic and cryptographic consistency of a 0206 case directory.
    """

    PROHIBITED_NOT_ANALYZED_PHRASES = [
        "no packing indicators identified",
        "no packing or compression indicators identified",
        "no anti-analysis evasions identified",
        "no anti-debugging or evasion checks identified",
        "no evasion techniques identified",
        "no packing heuristics triggered",
    ]

    CONTAINMENT_KEYWORDS = [
        "quarantine",
        "isolate",
        "block domain",
        "perimeter firewall",
        "containment action",
    ]

    def __init__(self):
        pass

    def validate_case(self, case_dir: Path | str) -> SemanticValidationResult:
        case_path = Path(case_dir).resolve()
        issues: List[ValidationIssue] = []

        if not case_path.exists() or not case_path.is_dir():
            return SemanticValidationResult(
                case_dir=str(case_path),
                status="FAIL",
                passed_checks=0,
                warning_checks=0,
                failed_checks=1,
                issues=[ValidationIssue(
                    rule="case_directory_exists",
                    severity="FAIL",
                    message=f"Directory does not exist or is not a directory: {case_path}"
                )]
            )

        # 1. Manifest Integrity
        issues.extend(self._validate_manifest_integrity(case_path))

        # Load core artifacts
        assessment = self._load_json(case_path / "assessment.json")
        coverage = self._load_json(case_path / "coverage.json")
        evidence = self._load_json(case_path / "evidence.json")
        findings = self._load_json(case_path / "findings.json")
        report = self._load_json(case_path / "report.json")
        report_md_path = case_path / "report.md"
        report_md = report_md_path.read_text(encoding="utf-8") if report_md_path.exists() else ""

        # 2. Coverage Consistency
        issues.extend(self._validate_coverage_consistency(coverage, assessment, report))

        # 3. Evidence Count Consistency
        issues.extend(self._validate_evidence_count_consistency(evidence, assessment, report, report_md))

        # 4. Finding Evidence References
        issues.extend(self._validate_finding_evidence_references(findings, evidence))

        # 5. Classification Consistency
        issues.extend(self._validate_classification_consistency(assessment, findings, evidence))

        # 6. Reputation Semantics
        issues.extend(self._validate_reputation_semantics(evidence, coverage, assessment))

        # 7. NOT_ANALYZED Semantics
        issues.extend(self._validate_not_analyzed_semantics(coverage, assessment, report_md))

        # 8. Score / Finding Consistency
        issues.extend(self._validate_score_finding_consistency(assessment, findings))

        # 9. Privacy-Safe Output
        issues.extend(self._validate_privacy_safe_output(case_path))

        # Calculate counts and status
        fails = [i for i in issues if i.severity == "FAIL"]
        warns = [i for i in issues if i.severity == "WARNING"]
        passes = [i for i in issues if i.severity == "PASS"]

        overall = "FAIL" if fails else ("WARNING" if warns else "PASS")

        return SemanticValidationResult(
            case_dir=str(case_path),
            status=overall,
            passed_checks=len(passes),
            warning_checks=len(warns),
            failed_checks=len(fails),
            issues=issues
        )

    def _load_json(self, path: Path) -> Optional[Any]:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _validate_manifest_integrity(self, case_dir: Path) -> List[ValidationIssue]:
        issues = []
        man_path = case_dir / "analysis_manifest.json"
        sha_path = case_dir / "analysis_manifest.sha256"

        if not man_path.exists():
            issues.append(ValidationIssue(
                rule="manifest_integrity",
                severity="FAIL",
                message="analysis_manifest.json missing.",
                artifact="analysis_manifest.json"
            ))
            return issues

        if not sha_path.exists():
            issues.append(ValidationIssue(
                rule="manifest_integrity",
                severity="FAIL",
                message="Companion analysis_manifest.sha256 missing.",
                artifact="analysis_manifest.sha256"
            ))
        else:
            try:
                calc_sha = hashlib.sha256(man_path.read_bytes()).hexdigest()
                expected_sha = sha_path.read_text(encoding="utf-8").strip().split()[0]
                if calc_sha.lower() != expected_sha.lower():
                    issues.append(ValidationIssue(
                        rule="manifest_integrity",
                        severity="FAIL",
                        message=f"Manifest sha256 hash mismatch! Calc: {calc_sha}, Expected: {expected_sha}",
                        artifact="analysis_manifest.sha256"
                    ))
                else:
                    issues.append(ValidationIssue(
                        rule="manifest_integrity",
                        severity="PASS",
                        message="Companion analysis_manifest.sha256 matches manifest hash.",
                        artifact="analysis_manifest.sha256"
                    ))
            except Exception as e:
                issues.append(ValidationIssue(
                    rule="manifest_integrity",
                    severity="FAIL",
                    message=f"Failed reading manifest hash: {e}",
                    artifact="analysis_manifest.sha256"
                ))

        # Check output artifact hashes in manifest
        try:
            man_data = json.loads(man_path.read_text(encoding="utf-8"))
            out_artifacts = man_data.get("output_artifacts", {})
            for name, meta in out_artifacts.items():
                art_file = case_dir / name
                if not art_file.exists():
                    issues.append(ValidationIssue(
                        rule="manifest_integrity",
                        severity="FAIL",
                        message=f"Output artifact listed in manifest is missing on disk: {name}",
                        artifact=name
                    ))
                else:
                    exp_hash = meta.get("sha256")
                    if exp_hash:
                        actual_hash = hashlib.sha256(art_file.read_bytes()).hexdigest()
                        if actual_hash.lower() != exp_hash.lower():
                            issues.append(ValidationIssue(
                                rule="manifest_integrity",
                                severity="FAIL",
                                message=f"Output artifact hash mismatch for {name}. Calc: {actual_hash}, Exp: {exp_hash}",
                                artifact=name
                            ))
        except Exception as e:
            issues.append(ValidationIssue(
                rule="manifest_integrity",
                severity="FAIL",
                message=f"Failed reading output_artifacts from manifest: {e}",
                artifact="analysis_manifest.json"
            ))

        return issues

    def _validate_coverage_consistency(
        self,
        coverage: Optional[Dict[str, Any]],
        assessment: Optional[Dict[str, Any]],
        report: Optional[Dict[str, Any]]
    ) -> List[ValidationIssue]:
        issues = []
        if coverage is None:
            issues.append(ValidationIssue(
                rule="coverage_consistency",
                severity="FAIL",
                message="coverage.json missing or invalid JSON.",
                artifact="coverage.json"
            ))
            return issues

        if assessment is None:
            issues.append(ValidationIssue(
                rule="coverage_consistency",
                severity="FAIL",
                message="assessment.json missing or invalid JSON.",
                artifact="assessment.json"
            ))
            return issues

        cov_matrix = coverage.get("domain_coverage") or {k: v for k, v in coverage.items() if isinstance(v, str)}
        ass_cov = assessment.get("coverage", {})
        ass_matrix = ass_cov.get("domain_coverage") or {k: v for k, v in ass_cov.items() if isinstance(v, str)}

        if not cov_matrix:
            issues.append(ValidationIssue(
                rule="coverage_consistency",
                severity="FAIL",
                message="coverage.json has empty domain_coverage.",
                artifact="coverage.json"
            ))
            return issues

        # Check coverage.json vs assessment.json coverage
        mismatches = []
        for dom, st in cov_matrix.items():
            ass_st = ass_matrix.get(dom)
            if ass_st != st:
                mismatches.append(f"{dom}: coverage.json='{st}' vs assessment.json='{ass_st}'")

        if mismatches:
            issues.append(ValidationIssue(
                rule="coverage_consistency",
                severity="FAIL",
                message=f"Coverage domain status discrepancy between coverage.json and assessment.json: {'; '.join(mismatches)}",
                artifact="coverage.json"
            ))
        else:
            issues.append(ValidationIssue(
                rule="coverage_consistency",
                severity="PASS",
                message="Coverage domain matrix identical between coverage.json and assessment.json.",
                artifact="coverage.json"
            ))

        # Check report.json if available
        if report and isinstance(report, dict):
            rep_cov = report.get("coverage") or report.get("assessment", {}).get("coverage", {})
            rep_matrix = rep_cov.get("domain_coverage") or {k: v for k, v in rep_cov.items() if isinstance(v, str)}
            if rep_matrix:
                rep_mismatches = []
                for dom, st in cov_matrix.items():
                    r_st = rep_matrix.get(dom)
                    if r_st != st:
                        rep_mismatches.append(f"{dom}: coverage.json='{st}' vs report.json='{r_st}'")
                if rep_mismatches:
                    issues.append(ValidationIssue(
                        rule="coverage_consistency",
                        severity="FAIL",
                        message=f"Coverage discrepancy with report.json: {'; '.join(rep_mismatches)}",
                        artifact="report.json"
                    ))

        return issues

    def _validate_evidence_count_consistency(
        self,
        evidence: Optional[Any],
        assessment: Optional[Dict[str, Any]],
        report: Optional[Dict[str, Any]],
        report_md: str
    ) -> List[ValidationIssue]:
        issues = []
        if evidence is None or not isinstance(evidence, list):
            issues.append(ValidationIssue(
                rule="evidence_count_consistency",
                severity="FAIL",
                message="evidence.json missing or not a JSON list.",
                artifact="evidence.json"
            ))
            return issues

        ev_count = len(evidence)
        if assessment:
            ass_nodes = assessment.get("evidence_graph_nodes")
            if ass_nodes != ev_count:
                issues.append(ValidationIssue(
                    rule="evidence_count_consistency",
                    severity="FAIL",
                    message=f"Evidence count discrepancy: evidence.json has {ev_count}, but assessment.evidence_graph_nodes is {ass_nodes}.",
                    artifact="assessment.json"
                ))
            else:
                issues.append(ValidationIssue(
                    rule="evidence_count_consistency",
                    severity="PASS",
                    message=f"Evidence count ({ev_count}) matches assessment.evidence_graph_nodes.",
                    artifact="assessment.json"
                ))

            # Check assessment summary string
            ass_summary = assessment.get("summary", "")
            match = re.search(r"evaluated\s+(\d+)\s+forensic\s+evidence", ass_summary, re.IGNORECASE)
            if match:
                summary_count = int(match.group(1))
                if summary_count != ev_count:
                    issues.append(ValidationIssue(
                        rule="evidence_count_consistency",
                        severity="FAIL",
                        message=f"assessment.summary states {summary_count} evidence records, but evidence.json contains {ev_count}.",
                        artifact="assessment.json"
                    ))

        if report and isinstance(report, dict):
            rep_ev = report.get("evidence_records", [])
            if len(rep_ev) != ev_count:
                issues.append(ValidationIssue(
                    rule="evidence_count_consistency",
                    severity="FAIL",
                    message=f"report.json evidence_records length ({len(rep_ev)}) != evidence.json length ({ev_count}).",
                    artifact="report.json"
                ))

        if report_md:
            match_md = re.search(r"Forensic Evidence (?:Records|Nodes):\*\*\s+(\d+)", report_md)
            if match_md:
                md_count = int(match_md.group(1))
                if md_count != ev_count:
                    issues.append(ValidationIssue(
                        rule="evidence_count_consistency",
                        severity="FAIL",
                        message=f"report.md states {md_count} evidence nodes, but evidence.json contains {ev_count}.",
                        artifact="report.md"
                    ))

        return issues

    def _validate_finding_evidence_references(
        self,
        findings: Optional[Any],
        evidence: Optional[Any]
    ) -> List[ValidationIssue]:
        issues = []
        if findings is None or not isinstance(findings, list):
            issues.append(ValidationIssue(
                rule="finding_evidence_references",
                severity="FAIL",
                message="findings.json missing or not a JSON list.",
                artifact="findings.json"
            ))
            return issues

        if evidence is None or not isinstance(evidence, list):
            return issues

        valid_eids = {r.get("evidence_id") for r in evidence if isinstance(r, dict) and r.get("evidence_id")}
        dangling_refs = []

        for f in findings:
            if not isinstance(f, dict):
                continue
            fid = f.get("finding_id", "UNKNOWN")
            eids = f.get("source_evidence_ids", []) or f.get("evidence_ids", [])
            for eid in eids:
                if eid not in valid_eids:
                    dangling_refs.append(f"{fid} -> {eid}")

        if dangling_refs:
            issues.append(ValidationIssue(
                rule="finding_evidence_references",
                severity="FAIL",
                message=f"Findings cite non-existent evidence IDs: {'; '.join(dangling_refs[:10])}",
                artifact="findings.json"
            ))
        else:
            issues.append(ValidationIssue(
                rule="finding_evidence_references",
                severity="PASS",
                message=f"All {len(findings)} findings cite verified evidence IDs in EvidenceStore.",
                artifact="findings.json"
            ))

        return issues

    def _validate_classification_consistency(
        self,
        assessment: Optional[Dict[str, Any]],
        findings: Optional[Any],
        evidence: Optional[Any]
    ) -> List[ValidationIssue]:
        issues = []
        if not assessment or not isinstance(assessment, dict):
            return issues

        classification = assessment.get("classification", "")
        # Rule: Never output legacy default "Suspicious.PE.Generic"
        if "suspicious.pe.generic" in classification.lower():
            issues.append(ValidationIssue(
                rule="classification_consistency",
                severity="FAIL",
                message="Legacy default 'Suspicious.PE.Generic' detected in classification. UNKNOWN / NOT_ESTABLISHED required when no findings exist.",
                artifact="assessment.json"
            ))

        num_findings = len(findings) if isinstance(findings, list) else 0

        # Check reputation status in evidence
        has_positive_rep = False
        if isinstance(evidence, list):
            for r in evidence:
                if isinstance(r, dict) and r.get("source_type") == "REPUTATION" and r.get("field") == "lookup_status":
                    if r.get("value") in ("KNOWN_MALICIOUS", "KNOWN_SUSPICIOUS"):
                        has_positive_rep = True

        if "unknown" in classification.lower() or (num_findings == 0 and not has_positive_rep):
            if num_findings == 0 and not has_positive_rep:
                if classification != "UNKNOWN / NOT_ESTABLISHED":
                    issues.append(ValidationIssue(
                        rule="classification_consistency",
                        severity="FAIL",
                        message=f"0 findings and no positive reputation must produce 'UNKNOWN / NOT_ESTABLISHED', but found: '{classification}'",
                        artifact="assessment.json"
                    ))
                else:
                    issues.append(ValidationIssue(
                        rule="classification_consistency",
                        severity="PASS",
                        message="Classification correctly evaluated as 'UNKNOWN / NOT_ESTABLISHED' for clean baseline.",
                        artifact="assessment.json"
                    ))

            # Confidence check: must not report 1.0 when classification is UNKNOWN
            class_conf = assessment.get("classification_confidence")
            if class_conf is None:
                class_conf = assessment.get("confidence", 0.0)
            if class_conf >= 0.99:
                issues.append(ValidationIssue(
                    rule="classification_consistency",
                    severity="FAIL",
                    message=f"Classification confidence cannot be 1.0 when classification is UNKNOWN / NOT_ESTABLISHED (found: {class_conf}).",
                    artifact="assessment.json"
                ))
            else:
                issues.append(ValidationIssue(
                    rule="classification_confidence",
                    severity="PASS",
                    message=f"Classification confidence is calibrated ({class_conf}) for UNKNOWN classification.",
                    artifact="assessment.json"
                ))

            # Purpose check
            purpose = assessment.get("purpose", "")
            if purpose and "suspicious execution or remote payload deployment" in purpose.lower():
                issues.append(ValidationIssue(
                    rule="classification_consistency",
                    severity="FAIL",
                    message=f"Unsupported generic purpose text detected on unestablished baseline: '{purpose}'",
                    artifact="assessment.json"
                ))
            elif purpose in ("NOT_ESTABLISHED", None, ""):
                issues.append(ValidationIssue(
                    rule="purpose_consistency",
                    severity="PASS",
                    message="Purpose correctly reported as NOT_ESTABLISHED when no hostile evidence exists.",
                    artifact="assessment.json"
                ))

        return issues

    def _validate_reputation_semantics(
        self,
        evidence: Optional[Any],
        coverage: Optional[Dict[str, Any]],
        assessment: Optional[Dict[str, Any]]
    ) -> List[ValidationIssue]:
        issues = []
        if not isinstance(evidence, list):
            return issues

        rep_status = None
        rep_ratio = None
        for r in evidence:
            if isinstance(r, dict) and r.get("source_type") == "REPUTATION":
                if r.get("field") == "lookup_status":
                    rep_status = r.get("value")
                elif r.get("field") == "detection_ratio":
                    rep_ratio = r.get("value")

        if rep_status in ("SKIPPED_OFFLINE", "NOT_CHECKED"):
            # Check coverage status
            cov_matrix = (coverage.get("domain_coverage") if coverage else {}) or {}
            rep_cov = cov_matrix.get("Reputation")
            if rep_cov == "COMPLETED":
                issues.append(ValidationIssue(
                    rule="reputation_semantics",
                    severity="FAIL",
                    message=f"Reputation coverage is 'COMPLETED' despite external lookup being {rep_status}. Must be SKIPPED_OFFLINE or NOT_CHECKED.",
                    artifact="coverage.json"
                ))
            else:
                issues.append(ValidationIssue(
                    rule="reputation_semantics",
                    severity="PASS",
                    message=f"Offline reputation coverage truthfully recorded as {rep_cov}.",
                    artifact="coverage.json"
                ))

            # Ratio must be N/A
            if rep_ratio not in ("N/A", None):
                issues.append(ValidationIssue(
                    rule="reputation_semantics",
                    severity="FAIL",
                    message=f"Offline reputation detection ratio must be 'N/A', but found: '{rep_ratio}'",
                    artifact="evidence.json"
                ))

        return issues

    def _validate_not_analyzed_semantics(
        self,
        coverage: Optional[Dict[str, Any]],
        assessment: Optional[Dict[str, Any]],
        report_md: str
    ) -> List[ValidationIssue]:
        issues = []
        cov_matrix = (coverage.get("domain_coverage") if coverage else {}) or {}
        cov_reasons = (coverage.get("coverage_reasons") if coverage else {}) or {}

        for dom, st in cov_matrix.items():
            if st == "NOT_ANALYZED":
                reason = cov_reasons.get(dom, "").lower()
                for phrase in self.PROHIBITED_NOT_ANALYZED_PHRASES:
                    if phrase in reason:
                        issues.append(ValidationIssue(
                            rule="not_analyzed_semantics",
                            severity="FAIL",
                            message=f"Domain '{dom}' is NOT_ANALYZED but reason implies analysis ran: '{cov_reasons.get(dom)}'",
                            artifact="coverage.json"
                        ))

        # Check markdown report text
        if report_md:
            for phrase in self.PROHIBITED_NOT_ANALYZED_PHRASES:
                if phrase in report_md.lower():
                    issues.append(ValidationIssue(
                        rule="not_analyzed_semantics",
                        severity="FAIL",
                        message=f"report.md contains prohibited negative claim for unanalyzed domain: '{phrase}'",
                        artifact="report.md"
                    ))

        if not any(i.rule == "not_analyzed_semantics" and i.severity == "FAIL" for i in issues):
            issues.append(ValidationIssue(
                rule="not_analyzed_semantics",
                severity="PASS",
                message="All NOT_ANALYZED domains preserve truthful unexecuted semantics.",
                artifact="coverage.json"
            ))

        return issues

    def _validate_score_finding_consistency(
        self,
        assessment: Optional[Dict[str, Any]],
        findings: Optional[Any]
    ) -> List[ValidationIssue]:
        issues = []
        if not assessment or not isinstance(assessment, dict):
            return issues

        num_findings = len(findings) if isinstance(findings, list) else 0
        threat_score = assessment.get("threat_score", 0)
        recs = assessment.get("recommendations", [])

        if num_findings == 0:
            if threat_score != 0:
                issues.append(ValidationIssue(
                    rule="score_finding_consistency",
                    severity="FAIL",
                    message=f"0 findings must result in threat_score=0, but found {threat_score}.",
                    artifact="assessment.json"
                ))
            else:
                issues.append(ValidationIssue(
                    rule="score_finding_consistency",
                    severity="PASS",
                    message="Threat score is 0 with 0 findings.",
                    artifact="assessment.json"
                ))

        if threat_score == 0:
            # Recommendations check: no active quarantine/containment recommendations
            found_containment = []
            for r in recs:
                for kw in self.CONTAINMENT_KEYWORDS:
                    if kw in r.lower():
                        found_containment.append(r)
            if found_containment:
                issues.append(ValidationIssue(
                    rule="score_finding_consistency",
                    severity="FAIL",
                    message=f"Clean baseline contains containment/quarantine recommendations: {found_containment}",
                    artifact="assessment.json"
                ))
            else:
                issues.append(ValidationIssue(
                    rule="score_finding_consistency",
                    severity="PASS",
                    message="Recommendations are appropriately advisory and non-alarmist for clean baseline.",
                    artifact="assessment.json"
                ))

        return issues

    def _validate_privacy_safe_output(self, case_dir: Path) -> List[ValidationIssue]:
        issues = []
        sensitive_patterns = [
            (r"/run/media/(?!<REDACTED_USER>)[^\"\s\n]+", "Linux removable mount path leaked"),
            (r"/media/(?!<REDACTED_USER>)[^\"\s\n]+", "Linux media mount path leaked"),
            (r"sk-[a-zA-Z0-9]{20,}", "Raw OpenAI/Anthropic API key leaked"),
        ]

        files_to_check = [
            "analysis_manifest.json",
            "assessment.json",
            "coverage.json",
            "evidence.json",
            "findings.json",
            "iocs.json",
            "report.json",
            "report.md"
        ]

        leaks = []
        for fn in files_to_check:
            fp = case_dir / fn
            if not fp.exists():
                continue
            text = fp.read_text(encoding="utf-8", errors="ignore")
            for pattern, desc in sensitive_patterns:
                matches = re.findall(pattern, text)
                if matches:
                    leaks.append(f"{fn}: {desc} ({matches[:2]})")

        if leaks:
            issues.append(ValidationIssue(
                rule="privacy_safe_output",
                severity="FAIL",
                message=f"Privacy leakage detected in case deliverables: {'; '.join(leaks)}",
                artifact="case_deliverables"
            ))
        else:
            issues.append(ValidationIssue(
                rule="privacy_safe_output",
                severity="PASS",
                message="Case deliverables are verified privacy-safe and free from sensitive host telemetry.",
                artifact="case_deliverables"
            ))

        return issues
