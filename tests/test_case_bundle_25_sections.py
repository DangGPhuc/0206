"""
Tests for Phase 18, 19, 20: 25-Section Domain Report Structure, Case Bundle Layout, and Adapters.
"""
import pytest
from pathlib import Path
from core.evidence import EvidenceStore
from reporting.basic.builder import BasicReportBuilder
from reporting.advanced.builder import AdvancedReportBuilder
from reporting.adapters.markdown_adapter import MarkdownReportAdapter
from reporting.adapters.generic_docx_adapter import GenericDOCXReportAdapter
from core.schemas import AnalysisDomain


def test_25_sections_builders():
    """Verify that BasicReportBuilder and AdvancedReportBuilder construct all 25 sections."""
    store = EvidenceStore()
    store.create("test.exe", "FILE_METADATA", "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Test", domain="PE")
    store.create("test.exe", "PE_HEADER", "machine_type", "x86", "Test", domain="PE")

    findings = [{
        "finding_id": "F-001",
        "title": "Suspicious Section",
        "status": "SUSPICIOUS_CAPABILITY",
        "domain": "PE",
        "source_evidence_ids": ["E-0001"]
    }]
    assessment = {
        "threat_score": 45,
        "threat_level": "MEDIUM",
        "classification": "Trojan.Generic",
        "summary": "Test assessment summary",
        "key_functionality": "Dropper activity",
        "purpose": "Evasion",
        "host_iocs": ["C:\\Windows\\Temp\\payload.bin"],
        "network_iocs": ["198.51.100.2"],
        "mitre_techniques": [{
            "technique_id": "T1055",
            "technique_name": "Process Injection",
            "tactic": "Defense Evasion",
            "status": "SUSPICIOUS_CAPABILITY",
            "evidence_ids": ["E-0001"]
        }],
        "coverage": {"ratio": "0.65", "domain_coverage": {"PE": "COMPLETED"}}
    }
    manifest = {
        "engine_name": "0206",
        "engine_version": "2.0.0",
        "case_id": "CASE-TEST-001",
        "sample_filename": "test.exe",
        "sample_hashes": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    }

    # Part I: Sections 1 to 7
    part1 = BasicReportBuilder.build_part1_data(store, findings, assessment, manifest)
    assert "summary" in part1
    assert "sample_identification" in part1
    assert "reputation" in part1
    assert "static_properties" in part1
    assert "basic_behavioral" in part1
    assert "initial_findings" in part1
    assert "initial_assessment" in part1

    # Part II: Sections 8 to 20 + Appendices 21 to 25
    part2 = AdvancedReportBuilder.build_part2_data(store, findings, assessment, manifest)
    # Sections 8 to 20
    assert "advanced_static" in part2
    assert "assembly_code" in part2
    assert "api_control_flow" in part2
    assert "advanced_dynamic" in part2
    assert "process_thread" in part2
    assert "memory_analysis" in part2
    assert "network_c2" in part2
    assert "persistence" in part2
    assert "anti_analysis" in part2
    assert "unpacking" in part2
    assert "dotnet_scripts_docs" in part2
    assert "cross_stage_correlation" in part2
    assert "final_assessment" in part2
    # Appendices 21 to 25
    assert "iocs" in part2
    assert "mitre_attack" in part2
    assert "coverage" in part2
    assert "evidence_appendix" in part2
    assert "analysis_manifest" in part2


def test_markdown_and_docx_render_25_sections(tmp_path: Path):
    """Verify that Markdown and DOCX adapters render all 25 sections cleanly."""
    store = EvidenceStore()
    store.create("test.exe", "FILE_METADATA", "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Test")

    session_data = {
        "manifest": {
            "engine_name": "0206",
            "engine_version": "2.0.0",
            "case_id": "CASE-TEST-25",
            "sample_filename": "test.exe",
            "sample_hashes": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
        },
        "assessment": {
            "threat_score": 75,
            "threat_level": "HIGH",
            "classification": "Ransomware.Test",
            "summary": "Ransomware activity detected",
            "coverage": {"ratio": "0.75", "domain_coverage": {"PE": "COMPLETED"}}
        },
        "findings": [],
        "evidence_records": [r.model_dump() for r in store.all()]
    }

    # Test Markdown rendering
    md_adapter = MarkdownReportAdapter()
    md_file = tmp_path / "report.md"
    md_adapter.render(session_data, md_file)
    assert md_file.exists()
    content = md_file.read_text(encoding="utf-8")

    # Check key 25-section markers
    assert "PART I — BASIC ANALYSIS" in content
    assert "PART II — ADVANCED ANALYSIS" in content
    assert "1. Summary" in content
    assert "8. Advanced Static Analysis" in content
    assert "18. .NET / Scripts / Documents where applicable" in content
    assert "21. IOC" in content
    assert "25. Analysis Manifest" in content
    assert "[NOT_ANALYZED]" in content

    # Test DOCX rendering
    docx_adapter = GenericDOCXReportAdapter()
    docx_file = tmp_path / "report.docx"
    docx_adapter.render(session_data, docx_file)
    assert docx_file.exists()
    assert docx_file.stat().st_size > 1000
