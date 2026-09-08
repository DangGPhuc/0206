"""
0206 - Part I (Basic Analysis) Report Builder
Phase 20: Extracts and structures Part I basic triage sections from EvidenceStore and findings.
"""
from typing import Dict, Any, List, Optional
from core.schemas import AnalysisDomain, CoverageStatus
from core.evidence import EvidenceStore


class BasicReportBuilder:
    """Extracts and structures Part I basic analysis data from session artifacts."""

    @staticmethod
    def build_part1_data(
        evidence_store: EvidenceStore,
        findings: List[Dict[str, Any]],
        assessment: Dict[str, Any],
        manifest: Dict[str, Any],
    ) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "title": "PART I — BASIC ANALYSIS",
            "sample_identification": {},
            "reputation": {},
            "basic_static": {},
            "basic_behavioral": {},
            "preliminary_findings": [],
            "initial_assessment": assessment,
        }

        # 1. Sample Identification
        file_meta = {r.field: r.value for r in evidence_store.find(source_type="FILE_METADATA")}
        pe_header = {r.field: r.value for r in evidence_store.find(source_type="PE_HEADER")}
        data["sample_identification"] = {
            "filename": manifest.get("sample_filename") or file_meta.get("filename", "unknown"),
            "sha256": manifest.get("sample_sha256") or file_meta.get("sha256", "N/A"),
            "sha1": file_meta.get("sha1", "N/A"),
            "md5": file_meta.get("md5", "N/A"),
            "file_size": file_meta.get("file_size", "N/A"),
            "file_type": pe_header.get("machine_type") or file_meta.get("file_type", "PE32/PE32+"),
            "architecture": pe_header.get("machine_type", "x86/x64"),
            "subsystem": pe_header.get("subsystem", "Windows GUI/CUI"),
            "entry_point": pe_header.get("entry_point_rva", "N/A"),
            "image_base": pe_header.get("image_base", "N/A"),
        }

        # 2. Reputation
        rep_records = evidence_store.find(source_type="REPUTATION")
        if rep_records:
            r = rep_records[0]
            prov = r.provenance or {}
            data["reputation"] = {
                "status": "COMPLETED",
                "provider": r.extractor,
                "detection_ratio": f"{prov.get('positives', 0)}/{prov.get('total', 0)}",
                "first_seen": prov.get("first_seen", "N/A"),
                "last_seen": prov.get("last_seen", "N/A"),
                "privacy_mode": manifest.get("privacy_mode", "strict (hash lookup only)"),
            }
        else:
            data["reputation"] = {
                "status": "NOT_ANALYZED",
                "details": "Reputation lookup not requested or offline mode enabled."
            }

        # 3. Basic Static Analysis
        sections = [r.value for r in evidence_store.find(field="section_info")]
        imports = [r.value for r in evidence_store.find(field="import")]
        exports = [r.value for r in evidence_store.find(field="export")]
        api_hashes = [r.value for r in evidence_store.find(field="api_hash")]
        urls = [r.value for r in evidence_store.find(field="url")]
        ips = [r.value for r in evidence_store.find(field="ipv4")]
        data["basic_static"] = {
            "status": "COMPLETED" if (sections or imports) else "NOT_ANALYZED",
            "section_count": len(sections),
            "sections": sections,
            "import_count": len(imports),
            "imports": imports[:30],
            "export_count": len(exports),
            "exports": exports[:20],
            "api_hashes": api_hashes[:10],
            "urls": urls[:20],
            "ips": ips[:20],
        }

        # 4. Basic Behavioral Analysis
        behav_proc = [r for r in evidence_store.find(source_type="PROCMON") if r.field == "process_create"]
        behav_file = [r for r in evidence_store.find(source_type="PROCMON") if "file" in r.field]
        behav_reg = [r for r in evidence_store.find(source_type="PROCMON") if "reg" in r.field]
        regshot = evidence_store.find(source_type="REGSHOT")
        if behav_proc or behav_file or behav_reg or regshot:
            data["basic_behavioral"] = {
                "status": "COMPLETED",
                "processes_spawned": len(behav_proc),
                "file_events": len(behav_file),
                "registry_events": len(behav_reg) + len(regshot),
            }
        else:
            data["basic_behavioral"] = {
                "status": "NOT_ANALYZED",
                "details": "No behavioral artifacts (Procmon CSV / Regshot) provided."
            }

        # 5. Preliminary Findings
        data["preliminary_findings"] = findings

        return data
