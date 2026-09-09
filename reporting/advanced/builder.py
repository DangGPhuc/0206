"""
0206 - Part II (Advanced Analysis) & Appendices Report Builder
Phase 18: Extracts and structures Part II advanced analysis sections (8 to 20)
and Appendices (21 to 25) from EvidenceStore, findings, and manifest.
Enforces that unsupported domains explicitly output [NOT_ANALYZED] without fabricating defaults.
"""
from typing import Dict, Any, List
from core.schemas import AnalysisDomain
from core.evidence import EvidenceStore


class AdvancedReportBuilder:
    """Extracts and structures Part II advanced analysis data and appendices from session artifacts."""

    @staticmethod
    def build_part2_data(
        evidence_store: EvidenceStore,
        findings: List[Dict[str, Any]],
        assessment: Dict[str, Any],
        manifest: Dict[str, Any],
    ) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "title": "PART II — ADVANCED ANALYSIS",
            # Sections 8 to 20
            "advanced_static": {},
            "assembly_code": {},
            "api_control_flow": {},
            "advanced_dynamic": {},
            "process_thread": {},
            "advanced_dynamic_process": {},  # backwards compatibility alias
            "memory_analysis": {},
            "network_c2": {},
            "persistence": {},
            "anti_analysis": {},
            "unpacking": {},
            "dotnet_scripts_docs": {},
            "cross_stage_correlation": {},
            "final_assessment": assessment,
            # Appendices 21 to 25
            "iocs": {},
            "mitre_attack": {},
            "coverage": {},
            "evidence_appendix": {},
            "analysis_manifest": {},
        }

        # 8. Advanced Static Analysis
        sec_anom = evidence_store.find(field="section_anomalies")
        embedded_pes = evidence_store.find(field="embedded_pe_in_resource")
        overlays = evidence_store.find(field="pe_overlay")
        adv_static_records = sec_anom + embedded_pes + overlays
        if adv_static_records:
            data["advanced_static"] = {
                "status": "COMPLETED",
                "details": f"Extracted {len(adv_static_records)} advanced static artifacts (overlays, anomalies, embedded resources).",
                "records": [r.value for r in adv_static_records[:10]]
            }
        else:
            data["advanced_static"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] No section anomalies or advanced loader artifacts extracted."
            }

        # 9. Assembly / Code Analysis
        rich_disasm = [
            r for r in evidence_store.all()
            if r.source_type in ("DECOMPILATION", "FUNCTION_ANALYSIS", "CONTROL_FLOW_GRAPH", "IDA_PRO", "GHIDRA", "RADARE2")
            or r.field in ("decompilation", "functions", "control_flow_graph", "cross_references")
        ]
        triage_disasm = evidence_store.find(source_type="DISASSEMBLY")
        code_structs = evidence_store.find(source_type="CODE_STRUCTURE")

        if rich_disasm:
            data["assembly_code"] = {
                "status": "COMPLETED",
                "tier": "ADVANCED_ASSEMBLY",
                "instruction_count": len(rich_disasm),
                "details": f"Advanced reverse engineering artifacts extracted ({len(rich_disasm)} records).",
            }
        elif triage_disasm or code_structs:
            instr_lines = [f"{r.source_offset or '0x00'}: {r.value}" for r in triage_disasm]
            data["assembly_code"] = {
                "status": "PARTIAL",
                "tier": "STATIC_CODE_TRIAGE",
                "instruction_count": len(triage_disasm),
                "instructions_preview": instr_lines[:25],
                "code_structures": [r.value for r in code_structs[:10]],
                "details": "Basic entry-point code triage completed via Capstone; interactive decompiler / full CFG analysis not executed.",
            }
        else:
            data["assembly_code"] = {
                "status": "NOT_ANALYZED",
                "tier": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] Disassembly engine not executed for this sample."
            }

        # 10. API / Control Flow
        static_imports = [r for r in evidence_store.all() if r.source_type == "PE_IMPORT" or r.field.startswith("imported_api")]
        api_hashes = [r for r in evidence_store.all() if r.field == "api_hash_match" or r.source_type in ("API_HASH", "API_HASH_CONSTANT")]
        api_refs = [r for r in evidence_store.all() if r.field == "api_reference" or r.source_type == "API_REFERENCE"]
        dyn_api_calls = [r for r in evidence_store.all() if r.source_type in ("DYNAMIC_API", "API_CALL", "PROCMON_API") or r.field in ("dynamic_api_call", "api_call")]
        api_resolutions = [r for r in evidence_store.all() if r.source_type == "API_RESOLUTION" or r.field in ("resolved_api", "dynamic_resolution")]
        xrefs = [r for r in evidence_store.all() if r.source_type == "XREF" or r.field == "xref"]
        control_flow = [r for r in evidence_store.all() if r.source_type in ("CONTROL_FLOW", "CFG") or r.field in ("control_flow", "branch_target")]

        advanced_api_records = dyn_api_calls + api_resolutions + xrefs + control_flow
        all_api_records = static_imports + api_hashes + api_refs + advanced_api_records

        if advanced_api_records:
            data["api_control_flow"] = {
                "status": "COMPLETED",
                "count": len(advanced_api_records),
                "dynamic_api_calls_count": len(dyn_api_calls),
                "api_resolutions_count": len(api_resolutions),
                "xrefs_count": len(xrefs),
                "control_flow_count": len(control_flow),
                "items": [r.value for r in advanced_api_records[:15]],
                "details": f"Captured {len(advanced_api_records)} advanced runtime API resolution and control-flow artifacts."
            }
        elif all_api_records:
            data["api_control_flow"] = {
                "status": "PARTIAL",
                "tier": "STATIC_IMPORT_TRIAGE",
                "count": len(all_api_records),
                "imported_apis_count": len(static_imports),
                "api_hashes_count": len(api_hashes),
                "items": [f"{r.field}: {r.value}" for r in (static_imports + api_hashes)[:15]],
                "details": f"Basic static IAT and {len(api_hashes)} API hash constants identified; dynamic API tracing and CFG not executed."
            }
        else:
            data["api_control_flow"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] No API resolution or control-flow analysis performed."
            }

        # 11. Advanced Behavioral Analysis
        dyn_records = [r for r in evidence_store.all() if r.domain in (AnalysisDomain.PROCESS, AnalysisDomain.FILESYSTEM, AnalysisDomain.REGISTRY)]
        if dyn_records:
            data["advanced_dynamic"] = {
                "status": "COMPLETED",
                "event_count": len(dyn_records),
                "details": f"Collected {len(dyn_records)} normalized behavioral event records from telemetry."
            }
        else:
            data["advanced_dynamic"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] Dynamic execution trace not available."
            }

        # 12. Process / Thread
        proc_records = [r for r in evidence_store.all() if r.domain in (AnalysisDomain.PROCESS, AnalysisDomain.THREAD)]
        data["process_thread"] = {
            "status": "COMPLETED" if proc_records else "NOT_ANALYZED",
            "count": len(proc_records),
            "items": [f"{r.field}: {r.value}" for r in proc_records[:10]],
            "details": f"Recorded {len(proc_records)} process and thread events." if proc_records else "[NOT_ANALYZED] No process tree or thread telemetry captured."
        }
        data["advanced_dynamic_process"] = data["process_thread"]

        # 13. Memory Analysis
        mem_records = [r for r in evidence_store.all() if r.domain == AnalysisDomain.MEMORY]
        data["memory_analysis"] = {
            "status": "COMPLETED" if mem_records else "NOT_ANALYZED",
            "count": len(mem_records),
            "items": [f"{r.field}: {r.value}" for r in mem_records[:10]],
            "details": f"Detected {len(mem_records)} in-memory artifacts." if mem_records else "[NOT_ANALYZED] No memory dump or PE-sieve injection scan provided."
        }

        # 14. Network / C2
        net_records = [r for r in evidence_store.all() if r.domain in (AnalysisDomain.NETWORK, AnalysisDomain.DNS, AnalysisDomain.HTTP, AnalysisDomain.TLS, AnalysisDomain.C2)]
        beacon_records = [r for r in net_records if "beacon" in r.field.lower()]
        data["network_c2"] = {
            "status": "COMPLETED" if net_records else "NOT_ANALYZED",
            "count": len(net_records),
            "beaconing_detected": len(beacon_records) > 0,
            "items": [f"{r.field}: {r.value}" for r in net_records[:15]],
            "details": f"Captured {len(net_records)} network communications / C2 indicators." if net_records else "[NOT_ANALYZED] No network traffic PCAP provided."
        }

        # 15. Persistence
        pers_records = [r for r in evidence_store.all() if r.domain == AnalysisDomain.PERSISTENCE]
        data["persistence"] = {
            "status": "COMPLETED" if pers_records else "NOT_ANALYZED",
            "count": len(pers_records),
            "items": [f"{r.field}: {r.value}" for r in pers_records[:10]],
            "details": f"Identified {len(pers_records)} persistence mechanisms." if pers_records else "[NOT_ANALYZED] No autostart or registry persistence mechanisms detected."
        }

        # 16. Anti-Analysis
        anti_records = [r for r in evidence_store.all() if r.domain == AnalysisDomain.ANTI_ANALYSIS]
        data["anti_analysis"] = {
            "status": "COMPLETED" if anti_records else "NOT_ANALYZED",
            "count": len(anti_records),
            "items": [f"{r.field}: {r.value}" for r in anti_records[:10]],
            "details": f"Detected {len(anti_records)} anti-analysis / evasion artifacts." if anti_records else "[NOT_ANALYZED] No anti-analysis mechanisms detected."
        }

        # 17. Packing / Unpacking
        pack_records = [r for r in evidence_store.all() if r.domain in (AnalysisDomain.PACKING, AnalysisDomain.UNPACKING)]
        data["unpacking"] = {
            "status": "COMPLETED" if pack_records else "NOT_ANALYZED",
            "count": len(pack_records),
            "items": [f"{r.field}: {r.value}" for r in pack_records[:10]],
            "details": f"Analyzed binary packing and crypter status ({len(pack_records)} indicators)." if pack_records else "[NOT_ANALYZED] No packing or unpacking indicators."
        }

        # 18. .NET / Scripts / Documents
        alt_records = [r for r in evidence_store.all() if r.domain in (AnalysisDomain.DOTNET, AnalysisDomain.SCRIPT, AnalysisDomain.DOCUMENT, AnalysisDomain.SHELLCODE)]
        data["dotnet_scripts_docs"] = {
            "status": "COMPLETED" if alt_records else "NOT_ANALYZED",
            "count": len(alt_records),
            "items": [f"{r.field}: {r.value}" for r in alt_records[:10]],
            "details": f"Identified {len(alt_records)} .NET/Script/Document/Shellcode artifacts." if alt_records else "[NOT_APPLICABLE] Native executable target; no managed .NET, document, or script wrappers detected."
        }

        # 19. Cross-Stage Correlation
        corr_findings = [f for f in findings if f.get("correlation_rule") or f.get("status") in ("CONFIRMED_BEHAVIOR", "INFERRED_BEHAVIOR")]
        data["cross_stage_correlation"] = {
            "status": "COMPLETED" if corr_findings else "NOT_ANALYZED",
            "correlated_findings_count": len(corr_findings),
            "correlated_findings": corr_findings[:10],
            "details": f"Correlated {len(corr_findings)} findings across static, behavioral, and reputation stages." if corr_findings else "[NOT_CONFIRMED] No cross-stage corroboration detected across multiple stages."
        }

        # 20. Final Assessment
        data["final_assessment"] = assessment

        # Appendices 21 to 25
        data["iocs"] = {
            "host_iocs": assessment.get("host_iocs", []),
            "network_iocs": assessment.get("network_iocs", []),
            "hashes": manifest.get("sample_hashes", {})
        }
        data["mitre_attack"] = {
            "techniques": assessment.get("mitre_techniques", [])
        }
        data["coverage"] = assessment.get("coverage", {})
        data["evidence_appendix"] = {
            "total_records": len(evidence_store),
            "sample_records": [r.model_dump() for r in evidence_store.all()[:30]]
        }
        data["analysis_manifest"] = manifest

        return data
