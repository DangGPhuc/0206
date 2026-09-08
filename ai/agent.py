"""
LLM Threat Synthesizer Module
Orchestrates AI-driven contextualization and incorporates an offline expert heuristic engine
for automated SANS FOR610 threat assessment.
"""
import os
import json
import re
from typing import Dict, Any, Optional, List
from ai.prompts import SYSTEM_PROMPT, ANALYSIS_PROMPT_TEMPLATE


class LLMThreatSynthesizer:
    """Synthesizes static & dynamic telemetry using LLMs or deterministic heuristic rules."""

    def __init__(
        self,
        provider: str = "auto",
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        model: Optional[str] = None
    ):
        self.provider = provider.lower()
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.api_base = api_base or os.getenv("OPENAI_API_BASE", "")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o")

        # Auto-detect mode
        if self.provider == "auto":
            if self.api_key:
                self.provider = "openai"
            elif self.api_base and "11434" in self.api_base:
                self.provider = "ollama"
            else:
                self.provider = "heuristic"

    def synthesize(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """Main synthesis entry point."""
        if self.provider in ("openai", "ollama") and (self.api_key or self.provider == "ollama"):
            try:
                return self._call_llm(telemetry)
            except Exception as e:
                # Log error and fallback seamlessly
                fallback_res = self._heuristic_synthesize(telemetry)
                fallback_res["llm_fallback_notice"] = f"LLM query failed ({e}). Reverted to offline heuristic engine."
                return fallback_res
        else:
            return self._heuristic_synthesize(telemetry)

    def _call_llm(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """Calls OpenAI or Ollama endpoint."""
        from openai import OpenAI
        client_kwargs: Dict[str, Any] = {}
        if self.api_base:
            client_kwargs["base_url"] = self.api_base
        if self.api_key:
            client_kwargs["api_key"] = self.api_key
        elif self.provider == "ollama":
            client_kwargs["api_key"] = "ollama"
            if not self.api_base:
                client_kwargs["base_url"] = "http://localhost:11434/v1"

        client = OpenAI(**client_kwargs)
        
        # Prepare telemetry summary to avoid exceeding token limit
        compact_telemetry = {
            "file_info": telemetry.get("static", {}).get("file_info", {}),
            "packed_analysis": telemetry.get("static", {}).get("packed_analysis", {}),
            "detected_capabilities": telemetry.get("static", {}).get("detected_capabilities", {}),
            "api_hashing_matches": telemetry.get("static", {}).get("api_hashing_matches", [])[:15],
            "anomalies": telemetry.get("static", {}).get("anomalies", []),
            "suspicious_strings": telemetry.get("static", {}).get("strings_analysis", {}).get("suspicious_commands", [])[:15],
            "network_artifacts": telemetry.get("behavioral", {}).get("network", {}),
            "host_behavior": telemetry.get("behavioral", {}).get("host_behavior", {})
        }

        user_prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            telemetry_json=json.dumps(compact_telemetry, indent=2)
        )

        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2,
            response_format={"type": "json_object"}
        )

        raw_content = response.choices[0].message.content or "{}"
        try:
            return json.loads(raw_content)
        except json.JSONDecodeError:
            # Clean markdown codeblocks if model added any
            cleaned = re.sub(r'^```json\s*', '', raw_content.strip())
            cleaned = re.sub(r'\s*```$', '', cleaned)
            return json.loads(cleaned)

    def _heuristic_synthesize(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deterministic expert heuristic engine based on SANS FOR610 & MITRE ATT&CK.
        Computes threat score and maps observations to IOCs, techniques, and narrative fields.
        """
        static_data = telemetry.get("static", {})
        behavioral_data = telemetry.get("behavioral", {})
        file_info = static_data.get("file_info", {})
        caps = static_data.get("detected_capabilities", {})
        anomalies = static_data.get("anomalies", [])
        api_hashes = static_data.get("api_hashing_matches", [])
        packed = static_data.get("packed_analysis", {}).get("is_packed", False)

        network = behavioral_data.get("network", {})
        host_beh = behavioral_data.get("host_behavior", {})

        score = 10
        mitre_list: List[Dict[str, str]] = []
        host_iocs: List[str] = []
        network_iocs: List[str] = []

        # Baseline file IOCs
        if file_info.get("sha256"):
            host_iocs.append(f"SHA256: {file_info.get('sha256')}")
        if file_info.get("imphash") and file_info.get("imphash") != "N/A":
            host_iocs.append(f"Imphash: {file_info.get('imphash')}")

        # Evaluate Static Capabilities
        if "Process Injection (T1055)" in caps:
            score += 25
            mitre_list.append({
                "technique_id": "T1055",
                "technique_name": "Process Injection",
                "tactic": "Defense Evasion / Privilege Escalation",
                "evidence": f"Imported APIs: {', '.join(caps['Process Injection (T1055)'])}"
            })

        if "Anti-Debugging & Evasion (T1497 / T1622)" in caps:
            score += 15
            mitre_list.append({
                "technique_id": "T1622",
                "technique_name": "Debugger Evasion",
                "tactic": "Defense Evasion",
                "evidence": f"Imported APIs: {', '.join(caps['Anti-Debugging & Evasion (T1497 / T1622)'])}"
            })

        if "Persistence (T1547 / T1053)" in caps:
            score += 15
            mitre_list.append({
                "technique_id": "T1547.001",
                "technique_name": "Registry Run Keys / Startup Folder",
                "tactic": "Persistence",
                "evidence": f"Imported APIs: {', '.join(caps['Persistence (T1547 / T1053)'])}"
            })

        if "Network Communication & C2 (T1071)" in caps:
            score += 15
            mitre_list.append({
                "technique_id": "T1071.001",
                "technique_name": "Web Protocols (HTTP/S)",
                "tactic": "Command and Control",
                "evidence": f"Imported APIs: {', '.join(caps['Network Communication & C2 (T1071)'])}"
            })

        # API Hashing
        if api_hashes:
            score += 20
            resolved_names = [f"{m['api']} ({m['algorithm']})" for m in api_hashes[:6]]
            mitre_list.append({
                "technique_id": "T1027.007",
                "technique_name": "Dynamic API Resolution",
                "tactic": "Defense Evasion",
                "evidence": f"Embedded API hash constants detected: {', '.join(resolved_names)}"
            })

        # Packed / High Entropy
        if packed:
            score += 15
            mitre_list.append({
                "technique_id": "T1027.002",
                "technique_name": "Software Packing",
                "tactic": "Defense Evasion",
                "evidence": f"High section entropy or packer heuristics: {'; '.join(static_data.get('packed_analysis', {}).get('reasons', []))}"
            })

        # Behavioral: Network
        dns_queries = network.get("dns_queries", [])
        for dns_item in dns_queries:
            domain = dns_item.get("domain", "")
            if domain:
                network_iocs.append(f"DNS Query: {domain}")
                for ip in dns_item.get("resolved_ips", []):
                    network_iocs.append(f"Resolved IP: {ip} ({domain})")

        http_reqs = network.get("http_requests", [])
        for req in http_reqs:
            url_str = f"http://{req.get('host', '')}{req.get('uri', '')}"
            network_iocs.append(f"HTTP {req.get('method', 'GET')}: {url_str}")
            if req.get("user_agent"):
                network_iocs.append(f"User-Agent: {req.get('user_agent')}")

        if dns_queries or http_reqs or network.get("c2_beacons"):
            score += 20
            mitre_list.append({
                "technique_id": "T1071",
                "technique_name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "evidence": f"Outbound network beacons observed ({len(dns_queries)} DNS queries, {len(http_reqs)} HTTP requests)"
            })

        # Behavioral: Host Dropped Files & Persistence
        dropped_files = host_beh.get("dropped_files", [])
        for df in dropped_files:
            host_iocs.append(f"Dropped File: {df.get('path')}")
            score += 15
            mitre_list.append({
                "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
                "evidence": f"Executable written to disk: {df.get('path')}"
            })

        pers_reg = host_beh.get("persistence_registry", [])
        for pr in pers_reg:
            host_iocs.append(f"Persistence Registry: {pr.get('key_path')} ({pr.get('detail', '')})")
            score += 20
            mitre_list.append({
                "technique_id": "T1547.001",
                "technique_name": "Registry Run Keys / Startup Folder",
                "tactic": "Persistence",
                "evidence": f"Registry Run key modified: {pr.get('key_path')}"
            })

        # Clamp threat score between 0 and 100
        threat_score = min(100, max(0, score))
        if threat_score >= 80:
            threat_level = "CRITICAL"
        elif threat_score >= 60:
            threat_level = "HIGH"
        elif threat_score >= 40:
            threat_level = "MEDIUM"
        elif threat_score >= 20:
            threat_level = "LOW"
        else:
            threat_level = "INFORMATIONAL / CLEAN"

        # Classification
        family = "Trojan.Generic"
        if "Process Injection (T1055)" in caps and network_iocs:
            family = "Trojan.Dropper / Injector / C2 Agent"
        elif "Cryptography & Ransomware (T1486)" in caps:
            family = "Ransomware.Generic"
        elif network_iocs and not caps.get("Process Injection (T1055)"):
            family = "Trojan.Downloader"
        elif pers_reg:
            family = "Backdoor / Persistent Trojan"

        # Formulate narratives
        executive_summary = (
            f"Automated static and behavioral triage indicates this sample is a {threat_level} threat "
            f"(Score: {threat_score}/100) identified as {family}. The binary exhibits capabilities for "
            f"{', '.join(caps.keys()) if caps else 'basic execution'}. "
            f"Host and network telemetry reveal active persistence establishment and outbound C2 connectivity."
        )

        key_functionality = (
            f"1. Evasion & Defense: Packed structure ({'Yes' if packed else 'No'}), "
            f"API Hashing ({len(api_hashes)} constants identified). "
            f"2. Execution & Injection: {'Detected memory manipulation and process injection capabilities' if 'Process Injection (T1055)' in caps else 'Standard user-mode process execution'}. "
            f"3. C2 Infrastructure: {len(network_iocs)} network indicators identified across DNS and HTTP protocols."
        )

        purpose = (
            "Attacker objective focuses on establishing an initial persistence footprint on the endpoint, "
            "evading standard EDR/AV static detection via dynamic API resolution, and opening a reverse C2 communication channel."
        )

        persistence = (
            f"Registry Run Keys / Autostart modifications identified: "
            f"{'; '.join([p.get('key_path', '') for p in pers_reg]) if pers_reg else 'No autostart registry entries observed during active trace.'}"
        )

        environment_impact = (
            "High risk of enterprise lateral movement, credential access, and persistent C2 staging. "
            "May permit remote execution of arbitrary payloads on compromised endpoint."
        )

        root_cause = "Likely distributed via spear-phishing attachment, malicious download, or secondary payload delivery."
        attribution = "Unattributed / Generic Commercial Cybercrime Tooling"

        recommendations = [
            "Immediately isolate the affected workstation from the corporate network.",
            f"Block observed network IOCs on perimeter firewalls and DNS sinkholes ({', '.join([i for i in network_iocs[:3]]) if network_iocs else 'N/A'}).",
            "Delete persistence registry keys and remove any dropped executable binaries from AppData/Temp.",
            "Perform enterprise-wide EDR threat hunting using the generated file SHA256 and imphash."
        ]

        return {
            "threat_level": threat_level,
            "threat_score": threat_score,
            "malware_family": family,
            "executive_summary": executive_summary,
            "key_functionality": key_functionality,
            "purpose": purpose,
            "persistence": persistence,
            "environment_impact": environment_impact,
            "root_cause": root_cause,
            "attribution": attribution,
            "mitre_attack": mitre_list,
            "key_iocs": {
                "host_iocs": list(set(host_iocs))[:20],
                "network_iocs": list(set(network_iocs))[:20]
            },
            "incident_recommendations": recommendations
        }
