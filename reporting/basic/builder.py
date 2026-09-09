"""
0206 - Part I (Basic Analysis) Report Builder
Phase 18: Extracts and structures Part I basic triage sections (1 to 7)
from EvidenceStore, findings, assessment, and manifest.
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
            "summary": {},
            "sample_identification": {},
            "reputation": {},
            "basic_static": {},
            "static_properties": {},
            "basic_behavioral": {},
            "initial_findings": findings,
            "preliminary_findings": findings,  # backward compatibility alias
            "initial_assessment": assessment,
        }

        # 1. Summary
        data["summary"] = {
            "threat_score": assessment.get("threat_score", 0),
            "threat_level": assessment.get("threat_level", "UNKNOWN"),
            "classification": assessment.get("classification", "Generic"),
            "summary_text": assessment.get("summary", ""),
            "key_functionality": assessment.get("key_functionality", ""),
            "purpose": assessment.get("purpose", "NOT_ESTABLISHED"),
            "status": "[OBSERVED]" if assessment.get("threat_score", 0) > 0 else "[NOT_CONFIRMED]"
        }

        # 2. Identification / IOCs
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

        # 3. Reputation
        rep_records = evidence_store.find(source_type="REPUTATION")
        ratio_rec = next((r for r in rep_records if r.field == "detection_ratio"), None)
        status_rec = next((r for r in rep_records if r.field == "lookup_status"), None)

        if ratio_rec or status_rec:
            r = ratio_rec or status_rec
            prov = r.provenance or {}
            lookup_status = prov.get("lookup_status") or (str(status_rec.value) if status_rec else "NOT_CHECKED")
            ratio_val = str(ratio_rec.value) if ratio_rec else "N/A"

            if lookup_status in ("NOT_CHECKED", "SKIPPED_OFFLINE", "LOOKUP_FAILED"):
                data["reputation"] = {
                    "status": lookup_status,
                    "provider": r.extractor or "VirusTotal",
                    "detection_ratio": "N/A",
                    "details": prov.get("details") or "External hash reputation lookup skipped in offline mode / no API key.",
                    "privacy_mode": manifest.get("privacy_mode", "strict (hash lookup only)"),
                }
            elif lookup_status == "NOT_FOUND":
                data["reputation"] = {
                    "status": "NOT_FOUND",
                    "provider": r.extractor or "VirusTotal",
                    "detection_ratio": "NOT_FOUND",
                    "details": "Hash not found in intelligence database (absence of intel != clean).",
                    "privacy_mode": manifest.get("privacy_mode", "strict (hash lookup only)"),
                }
            else:
                data["reputation"] = {
                    "status": "COMPLETED",
                    "provider": r.extractor or "VirusTotal",
                    "detection_ratio": ratio_val if ratio_val != "N/A" else f"{prov.get('positives', 0)}/{prov.get('total', 0)}",
                    "first_seen": prov.get("first_seen", "N/A"),
                    "last_seen": prov.get("last_analysis") or prov.get("last_seen", "N/A"),
                    "privacy_mode": manifest.get("privacy_mode", "strict (hash lookup only)"),
                }
        else:
            data["reputation"] = {
                "status": "NOT_ANALYZED",
                "details": "Reputation lookup not requested or offline mode enabled."
            }

        # 4. Static Properties Analysis
        sections = [r.value for r in evidence_store.find(field="section_info")]
        imports = [r.value for r in evidence_store.find(field="import")]
        exports = [r.value for r in evidence_store.find(field="export")]
        api_hashes = [r.value for r in evidence_store.find(field="api_hash_match")]
        urls = [r.value for r in evidence_store.find(field="embedded_url")]
        ips = [r.value for r in evidence_store.find(field="embedded_ip")]
        mutexes = [r.value for r in evidence_store.find(field="mutex_indicator")]
        overlays = [r.value for r in evidence_store.find(field="pe_overlay")]
        packers = [r.value for r in evidence_store.find(field="packer_assessment")]

        static_props = {
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
            "mutexes": mutexes[:10],
            "overlays": overlays[:2],
            "packer_assessment": packers[0] if packers else None,
        }
        data["basic_static"] = static_props
        data["static_properties"] = static_props

        # 5. Basic Behavioral Analysis (Artifact Ingestion Only)
        behav_proc = [r for r in evidence_store.find(source_type="PROCMON") if r.field == "process_create"]
        behav_file = [r for r in evidence_store.find(source_type="PROCMON") if "file" in r.field]
        behav_reg = [r for r in evidence_store.find(source_type="PROCMON") if "reg" in r.field]
        regshot = evidence_store.find(source_type="REGSHOT")
        if behav_proc or behav_file or behav_reg or regshot:
            data["basic_behavioral"] = {
                "status": "COMPLETED",
                "mode": "ARTIFACT_INGESTION",
                "processes_spawned": len(behav_proc),
                "file_events": len(behav_file),
                "registry_events": len(behav_reg) + len(regshot),
                "details": "Telemetry ingested from recorded capture artifacts (Procmon/Regshot). (Host safe: no live execution performed)."
            }
        else:
            data["basic_behavioral"] = {
                "status": "NOT_ANALYZED",
                "mode": "NONE",
                "details": "No behavioral artifacts (Procmon CSV / Regshot) provided."
            }

        # 6. Initial Findings
        data["initial_findings"] = findings

        # 7. Initial Assessment
        data["initial_assessment"] = assessment

        return data
