"""
0206 - Part II (Advanced Analysis) Report Builder
Phase 20: Extracts and structures Part II advanced analysis sections from EvidenceStore and findings.
Enforces that unsupported domains explicitly output [NOT_ANALYZED] without fabricating defaults.
"""
from typing import Dict, Any, List
from core.schemas import AnalysisDomain
from core.evidence import EvidenceStore


class AdvancedReportBuilder:
    """Extracts and structures Part II advanced analysis data from session artifacts."""

    @staticmethod
    def build_part2_data(
        evidence_store: EvidenceStore,
        findings: List[Dict[str, Any]],
        assessment: Dict[str, Any],
        manifest: Dict[str, Any],
    ) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "title": "PART II — ADVANCED ANALYSIS",
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
            "cross_stage_correlation": {},
            "final_assessment": assessment,
        }

        # 7. Advanced Static Analysis
        sec_anom = evidence_store.find(field="section_anomalies")
        data["advanced_static"] = {
            "status": "COMPLETED" if sec_anom else "NOT_ANALYZED",
            "details": "Section anomalies and PE header validation." if sec_anom else "[NOT_ANALYZED] No section anomalies or advanced loader artifacts extracted."
        }

        # 8. Assembly & Code Analysis (Static Code Triage vs Advanced Reverse Engineering)
        rich_disasm = [
            r for r in evidence_store.all()
            if r.source_type in ("DECOMPILATION", "FUNCTION_ANALYSIS", "CONTROL_FLOW_GRAPH", "IDA_PRO", "GHIDRA", "RADARE2")
            or r.field in ("decompilation", "functions", "control_flow_graph", "cross_references")
        ]
        triage_disasm = evidence_store.find(source_type="DISASSEMBLY")

        if rich_disasm:
            data["assembly_code"] = {
                "status": "COMPLETED",
                "tier": "ADVANCED_ASSEMBLY",
                "instruction_count": len(rich_disasm),
                "details": f"Advanced reverse engineering artifacts extracted ({len(rich_disasm)} records).",
            }
        elif triage_disasm:
            instr_lines = []
            for r in triage_disasm:
                instr_lines.append(f"{r.source_offset or '0x00'}: {r.value}")
            data["assembly_code"] = {
                "status": "PARTIAL",
                "tier": "STATIC_CODE_TRIAGE",
                "instruction_count": len(triage_disasm),
                "instructions_preview": instr_lines[:25],
                "details": "Basic entry-point code triage completed via Capstone; interactive decompiler / full CFG analysis not executed.",
            }
        else:
            data["assembly_code"] = {
                "status": "NOT_ANALYZED",
                "tier": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] Disassembly engine not executed for this sample."
            }

        # 9. API & Control Flow Analysis (Distinguish Static Imports/Hashes from Dynamic/Control Flow)
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
                "count": len(all_api_records),
                "static_imports_count": len(static_imports),
                "api_hashes_count": len(api_hashes),
                "items": [r.value for r in all_api_records[:15]],
                "details": "Static API imports and precomputed API hash constants identified; dynamic runtime API calls and control-flow cross-references not captured or analyzed."
            }
        else:
            data["api_control_flow"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] No dynamic API resolution or control flow cross-references detected."
            }

        # 10. Advanced Dynamic Analysis (Stage-aware query, no invalid DYNAMIC domain)
        dyn_source_types = ("SANDBOX", "DYNAMIC_TRACE", "ETW", "PROCMON", "PCAP", "PROCMON_PROCESS", "PROCMON_FILE", "PROCMON_REG", "PROCMON_REGISTRY")
        dyn_events = [r for r in evidence_store.all() if r.source_type in dyn_source_types]
        if dyn_events:
            data["advanced_dynamic"] = {
                "status": "COMPLETED",
                "event_count": len(dyn_events),
                "details": f"Captured {len(dyn_events)} dynamic execution traces from {', '.join(sorted({r.source_type for r in dyn_events}))}."
            }
        else:
            data["advanced_dynamic"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] Dynamic execution trace or sandbox telemetry not provided."
            }

        # 11. Process / Thread Analysis
        proc_events = evidence_store.find(domain="PROCESS")
        thread_events = evidence_store.find(domain="THREAD")
        if proc_events or thread_events:
            data["process_thread"] = {
                "status": "COMPLETED",
                "process_count": len(proc_events),
                "thread_count": len(thread_events),
                "details": f"Observed {len(proc_events)} process events and {len(thread_events)} thread events."
            }
        else:
            data["process_thread"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] No process tree or thread injection events recorded."
            }
        # Backwards compatibility alias
        data["advanced_dynamic_process"] = data["process_thread"]

        # 11. Memory Analysis
        mem_events = evidence_store.find(domain="MEMORY")
        if mem_events:
            data["memory_analysis"] = {
                "status": "COMPLETED",
                "count": len(mem_events),
                "details": [r.value for r in mem_events[:10]],
            }
        else:
            data["memory_analysis"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] No memory dump or Volatility/pe-sieve artifacts provided."
            }

        # 12. Network / C2 Analysis
        pcap_records = evidence_store.find(source_type="PCAP")
        if pcap_records:
            dns_queries = [r.value for r in pcap_records if r.field == "dns_query"]
            http_reqs = [r.value for r in pcap_records if r.field == "http_request"]
            beacon_scores = [r.value for r in pcap_records if r.field == "beacon_score"]
            data["network_c2"] = {
                "status": "COMPLETED",
                "total_events": len(pcap_records),
                "dns_queries": dns_queries[:15],
                "http_requests": http_reqs[:15],
                "beacon_analysis": beacon_scores[0] if beacon_scores else "No high-confidence beaconing observed.",
            }
        else:
            data["network_c2"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] No PCAP capture provided."
            }

        # 13. Persistence
        persist_records = evidence_store.find(domain="PERSISTENCE")
        if persist_records:
            data["persistence"] = {
                "status": "COMPLETED",
                "mechanisms": [r.value for r in persist_records]
            }
        else:
            data["persistence"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] Dedicated host persistence artifact inspection not engaged in profile."
            }

        # 14. Anti-Analysis
        anti_records = evidence_store.find(domain="ANTI_ANALYSIS")
        if anti_records:
            data["anti_analysis"] = {
                "status": "COMPLETED",
                "indicators": [r.value for r in anti_records]
            }
        else:
            data["anti_analysis"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] Dedicated anti-analysis and evasion detection not engaged in profile."
            }

        # 15. Unpacking
        unpack_records = evidence_store.find(domain="UNPACKING") + evidence_store.find(domain="PACKING")
        if unpack_records:
            data["unpacking"] = {
                "status": "COMPLETED",
                "observations": [f"{r.field}: {r.value}" for r in unpack_records]
            }
        else:
            data["unpacking"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] Dynamic unpacking and payload extraction not engaged in profile."
            }

        # 16. Cross-Stage Correlation & Final Synthesis
        confirmed_behaviors = [f for f in findings if f.get("status") == "CONFIRMED_BEHAVIOR"]
        data["cross_stage_correlation"] = {
            "status": "COMPLETED" if confirmed_behaviors else "PARTIAL",
            "confirmed_behaviors": confirmed_behaviors,
            "correlation_summary": (
                f"Successfully correlated {len(confirmed_behaviors)} static capabilities with confirmed runtime events."
                if confirmed_behaviors else
                "No cross-stage correlations confirmed; capabilities remain unverified by runtime telemetry."
            )
        }

        return data
