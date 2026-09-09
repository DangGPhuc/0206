"""
0206 - AI Grounding Validator
Phase 16 & 17: Grounding and evidence boundary validator.
Validates AI generated hypotheses, IOCs, and MITRE techniques against the EvidenceStore.
Enforces that AI can NEVER invent IOCs, override threat scores, or cite phantom evidence IDs.
"""
import re
from typing import Dict, Any, List, Optional
from core.schemas import AnalysisDomain, Classification
from core.evidence import EvidenceStore
from core.findings import Finding, Assessment
from ai.validation.schema import (
    AIFieldStatus,
    AIValidationDecision,
    AIValidationResult,
)


TECHNIQUE_RELEVANCE = {
    # T1055 Process Injection requires PROCESS, API, or MEMORY
    "T1055": {
        "domains": {"PROCESS", "API", "MEMORY"},
        "source_types": {"PROCMON_PROCESS", "API_RESOLUTION", "API_CALL", "DYNAMIC_API", "PROCESS", "PE_IMPORT", "BINARY_DATA"},
        "fields": {"process_create", "injected_thread", "imported_api_injection", "api_hash_match", "direct_syscall"},
        "excluded_fields": {"sha256", "md5", "sha1", "file_size", "overall_entropy", "imphash"}
    },
    # T1547 / T1543 Host Persistence requires PERSISTENCE, REGISTRY, FILESYSTEM
    "T1547": {
        "domains": {"PERSISTENCE", "REGISTRY", "FILESYSTEM"},
        "source_types": {"PROCMON_REG", "PROCMON_REGISTRY", "REGSHOT_MODIFIED", "PROCMON_FILE"},
        "fields": {"registry_persistence", "embedded_registry_key", "autostart_location"},
        "excluded_fields": {"sha256", "md5", "sha1", "file_size", "overall_entropy", "imphash"}
    },
    "T1543": {
        "domains": {"PERSISTENCE", "REGISTRY", "FILESYSTEM"},
        "source_types": {"PROCMON_REG", "PROCMON_REGISTRY", "REGSHOT_MODIFIED", "PROCMON_FILE"},
        "fields": {"registry_persistence", "embedded_registry_key", "autostart_location"},
        "excluded_fields": {"sha256", "md5", "sha1", "file_size", "overall_entropy", "imphash"}
    },
    # T1071 / T1041 / T1571 / T1090 Network C2 / Exfiltration requires NETWORK, C2, DNS, HTTP, TLS
    "T1071": {
        "domains": {"NETWORK", "C2", "DNS", "HTTP", "TLS"},
        "source_types": {"PCAP", "PCAP_DNS", "PCAP_HTTP", "NETWORK", "DNS", "HTTP", "TLS", "BEACON"},
        "fields": {"dns_query", "http_request", "embedded_url", "embedded_ip", "beacon_analysis"},
        "excluded_fields": {"sha256", "md5", "sha1", "file_size", "overall_entropy", "imphash"}
    },
    "T1041": {
        "domains": {"NETWORK", "C2", "DNS", "HTTP", "TLS"},
        "source_types": {"PCAP", "PCAP_DNS", "PCAP_HTTP", "NETWORK", "DNS", "HTTP", "TLS", "BEACON"},
        "fields": {"dns_query", "http_request", "embedded_url", "embedded_ip", "beacon_analysis"},
        "excluded_fields": {"sha256", "md5", "sha1", "file_size", "overall_entropy", "imphash"}
    },
    "T1571": {
        "domains": {"NETWORK", "C2", "DNS", "HTTP", "TLS"},
        "source_types": {"PCAP", "PCAP_DNS", "PCAP_HTTP", "NETWORK", "DNS", "HTTP", "TLS", "BEACON"},
        "fields": {"dns_query", "http_request", "embedded_url", "embedded_ip", "beacon_analysis"},
        "excluded_fields": {"sha256", "md5", "sha1", "file_size", "overall_entropy", "imphash"}
    },
    "T1090": {
        "domains": {"NETWORK", "C2", "DNS", "HTTP", "TLS"},
        "source_types": {"PCAP", "PCAP_DNS", "PCAP_HTTP", "NETWORK", "DNS", "HTTP", "TLS", "BEACON"},
        "fields": {"dns_query", "http_request", "embedded_url", "embedded_ip", "beacon_analysis"},
        "excluded_fields": {"sha256", "md5", "sha1", "file_size", "overall_entropy", "imphash"}
    },
}


class GroundingValidator:
    """Validates and filters AI-suggested content against ground-truth forensic evidence."""

    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store

    def validate_synthesis(
        self,
        ai_dict: Dict[str, Any],
        baseline: Assessment,
        findings: Optional[List[Finding]] = None
    ) -> tuple[Assessment, AIValidationResult]:
        """
        Merges AI output into baseline assessment while strictly enforcing evidence grounding.
        """
        val_result = AIValidationResult()

        def add_decision(field: str, status: AIFieldStatus, reason: str, orig: Any = None, res: Any = None):
            d = AIValidationDecision(
                field=field, status=status, reason=reason,
                original_value=orig, resolved_value=res
            )
            val_result.decisions.append(d)
            val_result.decisions_by_field[field] = d.model_dump()
            if status == AIFieldStatus.REJECTED:
                val_result.rejected_fields.append(field)
            elif status == AIFieldStatus.DOWNGRADED:
                val_result.downgraded_fields.append(field)
            elif status == AIFieldStatus.ACCEPTED:
                val_result.accepted_fields.append(field)

        # 1. Threat score: AI CANNOT override deterministic score
        proposed_score = ai_dict.get("threat_score")
        if proposed_score is not None and proposed_score != baseline.threat_score:
            add_decision(
                "threat_score", AIFieldStatus.REJECTED,
                f"AI proposed score {proposed_score} was rejected. Deterministic score {baseline.threat_score} is authoritative.",
                proposed_score, baseline.threat_score
            )
        else:
            add_decision("threat_score", AIFieldStatus.ACCEPTED, "Deterministic score maintained.")

        # 2. Threat level: AI CANNOT override deterministic level
        proposed_level = ai_dict.get("threat_level")
        if proposed_level is not None and proposed_level != baseline.threat_level:
            add_decision(
                "threat_level", AIFieldStatus.REJECTED,
                f"AI proposed level '{proposed_level}' was rejected. Deterministic level '{baseline.threat_level}' is authoritative.",
                proposed_level, baseline.threat_level
            )
        else:
            add_decision("threat_level", AIFieldStatus.ACCEPTED, "Deterministic level maintained.")

        # 3. Structured Classification: hypothesis stored cleanly without string concatenation
        proposed_family = ai_dict.get("malware_family") or (ai_dict.get("classification") if ai_dict.get("classification") != baseline.classification else None)
        resolved_classification = baseline.classification
        classification_details = (
            baseline.classification_details.model_copy()
            if baseline.classification_details is not None
            else Classification(value=resolved_classification)
        )

        if proposed_family and proposed_family not in ("UNKNOWN", "Generic Suspicious", baseline.classification):
            corroborated = findings and len([f for f in findings if f.confidence >= 0.8]) >= 3
            classification_details.hypothesis = proposed_family
            if corroborated:
                classification_details.hypothesis_status = "CORROBORATED"
                add_decision(
                    "malware_family", AIFieldStatus.ACCEPTED,
                    f"Family hypothesis '{proposed_family}' corroborated by multi-stage findings.",
                    proposed_family, proposed_family
                )
            else:
                classification_details.hypothesis_status = "UNCONFIRMED"
                add_decision(
                    "malware_family", AIFieldStatus.DOWNGRADED,
                    f"Family hypothesis '{proposed_family}' recorded as UNCONFIRMED; insufficient corroborating findings.",
                    proposed_family, None
                )
        else:
            add_decision("malware_family", AIFieldStatus.ACCEPTED, "Baseline classification preserved.", None, baseline.classification)

        # 3b. Raw IOCs & behavioral claims validation
        for ioc_field in ("host_iocs", "network_iocs", "hashes", "paths", "domains", "ips", "ioc_values"):
            if ioc_field in ai_dict:
                add_decision(
                    ioc_field, AIFieldStatus.REJECTED,
                    f"IOC field '{ioc_field}' cannot be authored by AI; strictly derived from EvidenceStore facts.",
                    ai_dict.get(ioc_field), getattr(baseline, ioc_field, None)
                )

        if "c2_confirmation" in ai_dict:
            has_c2_fact = any("CONFIRMED_C2" in getattr(f, "title", "") for f in findings or [])
            if not has_c2_fact:
                add_decision(
                    "c2_confirmation", AIFieldStatus.REJECTED,
                    "AI C2 confirmation rejected; multi-source corroboration required for confirmed C2.",
                    ai_dict.get("c2_confirmation"), False
                )
            else:
                add_decision(
                    "c2_confirmation", AIFieldStatus.ACCEPTED,
                    "C2 confirmation grounded in verified multi-source evidence.",
                    ai_dict.get("c2_confirmation"), True
                )

        if "process_injection_confirmation" in ai_dict:
            add_decision(
                "process_injection_confirmation", AIFieldStatus.DOWNGRADED,
                "Process injection confirmation downgraded; static API imports establish potential capability only, not confirmed execution.",
                ai_dict.get("process_injection_confirmation"), "CAPABILITY_UNCONFIRMED_RUNTIME"
            )

        if "persistence_claims" in ai_dict:
            has_pers = any(
                getattr(f, "domain", None) in (AnalysisDomain.PERSISTENCE, AnalysisDomain.REGISTRY) or
                getattr(f, "category", None) == "PERSISTENCE"
                for f in findings or []
            )
            if not has_pers:
                add_decision(
                    "persistence_claims", AIFieldStatus.REJECTED,
                    "Persistence claim rejected; no autostart registry or service evidence found in EvidenceStore.",
                    ai_dict.get("persistence_claims"), None
                )
            else:
                add_decision(
                    "persistence_claims", AIFieldStatus.ACCEPTED,
                    "Persistence claim corroborated by host telemetry evidence.",
                    ai_dict.get("persistence_claims"), baseline.persistence_assessment
                )

        # 4. MITRE ATT&CK: Validate cited evidence IDs AND semantic relevance
        validated_mitre = list(baseline.mitre_techniques)
        mitre_entries = ai_dict.get("mitre_attack") or ai_dict.get("mitre_techniques") or []
        for t in mitre_entries:
            eids = t.get("evidence_ids", [])
            valid_eids = [eid for eid in eids if self.evidence_store.get(eid)]
            tech_id = t.get("technique_id", "")
            tech_prefix = tech_id.split(".")[0] if tech_id else ""
            cfg = TECHNIQUE_RELEVANCE.get(tech_id) or TECHNIQUE_RELEVANCE.get(tech_prefix)

            relevant_eids = []
            irrelevant_eids = []
            for eid in valid_eids:
                rec = self.evidence_store.get(eid)
                if not rec:
                    continue
                rec_dom = rec.domain.value if hasattr(rec.domain, "value") else str(rec.domain)
                rec_source = getattr(rec, "source_type", "")
                rec_field = getattr(rec, "field", "")
                if cfg:
                    if rec_field in cfg.get("excluded_fields", set()):
                        irrelevant_eids.append(eid)
                        continue
                    is_match = (
                        (cfg.get("domains") and rec_dom in cfg["domains"]) or
                        (cfg.get("source_types") and rec_source in cfg["source_types"]) or
                        (cfg.get("fields") and rec_field in cfg["fields"])
                    )
                    if not is_match:
                        irrelevant_eids.append(eid)
                        continue
                relevant_eids.append(eid)

            if relevant_eids:
                t["evidence_ids"] = relevant_eids
                validated_mitre.append(t)
                if irrelevant_eids:
                    add_decision(
                        f"mitre_technique_{tech_id}", AIFieldStatus.DOWNGRADED,
                        f"Technique cited verified evidence IDs {relevant_eids}; rejected irrelevant IDs {irrelevant_eids}.",
                        eids, relevant_eids
                    )
                else:
                    add_decision(
                        f"mitre_technique_{tech_id}", AIFieldStatus.ACCEPTED,
                        f"Technique cited verified relevant evidence IDs: {relevant_eids}",
                        eids, relevant_eids
                    )
            else:
                add_decision(
                    f"mitre_technique_{tech_id or 'unknown'}", AIFieldStatus.REJECTED,
                    f"Technique rejected because cited evidence IDs {eids} are missing or semantically irrelevant.",
                    eids, None
                )

        # 5. Narrative summaries: validate against unsupported strong claims
        exec_summary = ai_dict.get("executive_summary")
        strong_claims = ["confirmed", "established", "executed", "persisted", "exfiltrated", "c2", "injected", "unpacked"]
        unsupported_claims = []
        if exec_summary:
            summary_lower = exec_summary.lower()
            has_dynamic_exec = any(r.source_type in ("SANDBOX", "DYNAMIC_TRACE", "PROCMON", "PCAP") for r in self.evidence_store.all())

            for claim in strong_claims:
                if re.search(r'\b' + re.escape(claim) + r'\b', summary_lower):
                    corroborated = False
                    if claim in ("confirmed", "established"):
                        corroborated = baseline.threat_score >= 40 and len(findings or []) > 0
                    elif claim == "executed":
                        corroborated = has_dynamic_exec
                    elif claim == "persisted":
                        corroborated = any(f.domain in (AnalysisDomain.PERSISTENCE, AnalysisDomain.REGISTRY) for f in findings or [])
                    elif claim in ("c2", "exfiltrated"):
                        corroborated = any(f.domain in (AnalysisDomain.NETWORK, AnalysisDomain.C2) for f in findings or [])
                    elif claim == "injected":
                        corroborated = any(f.domain in (AnalysisDomain.PROCESS, AnalysisDomain.MEMORY) for f in findings or [])
                    elif claim == "unpacked":
                        corroborated = any("unpack" in f.title.lower() for f in findings or [])

                    if not corroborated:
                        unsupported_claims.append(claim)

            if unsupported_claims:
                if baseline.threat_score == 0 and not findings:
                    # Clean/zero baseline cannot have strong hostile narratives
                    exec_summary = baseline.summary
                    add_decision(
                        "executive_summary", AIFieldStatus.REJECTED,
                        f"AI narrative rejected due to unsupported strong claim(s): {unsupported_claims} on clean sample.",
                        ai_dict.get("executive_summary"), exec_summary
                    )
                else:
                    exec_summary += f" [Note: Claim(s) of '{', '.join(unsupported_claims)}' unconfirmed by deterministic findings]."
                    add_decision(
                        "executive_summary", AIFieldStatus.DOWNGRADED,
                        f"AI narrative downgraded due to uncorroborated claim(s): {unsupported_claims}.",
                        ai_dict.get("executive_summary"), exec_summary
                    )
            else:
                add_decision("executive_summary", AIFieldStatus.ACCEPTED, "Grounded executive narrative accepted.", None, None)
        else:
            exec_summary = baseline.summary
            add_decision("executive_summary", AIFieldStatus.ACCEPTED, "Baseline executive narrative preserved.", None, None)

        # 6. Recommendations: prevent generic containment on zero score
        proposed_recs = ai_dict.get("incident_recommendations")
        if proposed_recs and isinstance(proposed_recs, list):
            if baseline.threat_score == 0 and not findings:
                containment_terms = ["block", "isolate", "quarantine", "disconnect", "firewall", "remediate"]
                has_containment = any(any(term in str(r).lower() for term in containment_terms) for r in proposed_recs)
                if has_containment:
                    recommendations = baseline.recommendations
                    add_decision(
                        "recommendations", AIFieldStatus.REJECTED,
                        "AI containment recommendations rejected because baseline score is 0 with no findings.",
                        proposed_recs, baseline.recommendations
                    )
                else:
                    recommendations = proposed_recs
                    add_decision("recommendations", AIFieldStatus.ACCEPTED, "Advisory response recommendations accepted.", None, None)
            else:
                recommendations = proposed_recs
                add_decision("recommendations", AIFieldStatus.ACCEPTED, "Advisory response recommendations accepted.", None, None)
        else:
            recommendations = baseline.recommendations
            add_decision("recommendations", AIFieldStatus.ACCEPTED, "Baseline recommendations preserved.", None, None)

        merged = Assessment(
            assessment_id=baseline.assessment_id,
            title=f"Triage Assessment: {resolved_classification}",
            threat_level=baseline.threat_level,
            threat_score=baseline.threat_score,
            classification=resolved_classification,
            classification_details=classification_details,
            score_breakdown=baseline.score_breakdown,
            summary=exec_summary,
            key_functionality=ai_dict.get("key_functionality", baseline.key_functionality),
            purpose=ai_dict.get("purpose", baseline.purpose),
            persistence_assessment=baseline.persistence_assessment,
            runtime_confirmation_status=baseline.runtime_confirmation_status,
            mitre_techniques=validated_mitre,
            host_iocs=baseline.host_iocs,
            network_iocs=baseline.network_iocs,
            recommendations=recommendations,
            supporting_finding_ids=baseline.supporting_finding_ids,
            ai_validation=val_result.model_dump()
        )

        return merged, val_result
