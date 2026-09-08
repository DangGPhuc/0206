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
            "advanced_dynamic_process": {},
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

        # 8. Assembly & Code Analysis (Capstone triage / disassemblers)
        disasm_records = evidence_store.find(source_type="DISASSEMBLY")
        if disasm_records:
            instr_lines = []
            for r in disasm_records:
                instr_lines.append(f"{r.source_offset or '0x00'}: {r.value}")
            data["assembly_code"] = {
                "status": "COMPLETED",
                "instruction_count": len(disasm_records),
                "instructions_preview": instr_lines[:25],
            }
        else:
            data["assembly_code"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] Disassembly engine not executed for this sample."
            }

        # 9. API & Control Flow Analysis
        dyn_api = [r for r in evidence_store.all() if "api" in r.field.lower()]
        if dyn_api:
            data["api_control_flow"] = {
                "status": "COMPLETED",
                "count": len(dyn_api),
                "items": [r.value for r in dyn_api[:15]]
            }
        else:
            data["api_control_flow"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] No dynamic API resolution or control flow cross-references detected."
            }

        # 10. Advanced Dynamic / Process / Thread Analysis
        proc_events = evidence_store.find(domain="PROCESS")
        thread_events = evidence_store.find(domain="THREAD")
        if proc_events or thread_events:
            data["advanced_dynamic_process"] = {
                "status": "COMPLETED",
                "process_count": len(proc_events),
                "thread_count": len(thread_events),
            }
        else:
            data["advanced_dynamic_process"] = {
                "status": "NOT_ANALYZED",
                "details": "[NOT_ANALYZED] Dynamic execution trace not provided."
            }

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
                "details": "[NOT_ANALYZED] No persistence indicators observed in triage data."
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
                "details": "[NOT_ANALYZED] No anti-debugging or evasion checks identified."
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
                "details": "[NOT_ANALYZED] No automated unpacking or entropy shifts recorded."
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
