"""
LLM Prompts and JSON Schema definitions for AI-Assisted Malware Triage.
"""

SYSTEM_PROMPT = """You are a Principal Malware Reverse Engineer and Threat Intelligence Analyst holding SANS GREM (GIAC Reverse Engineering Malware) certification.
Your task is to analyze static PE metadata, behavioral network/host traces, and extracted strings to produce a comprehensive, structured threat assessment following the SANS FOR610 methodology.

You MUST respond strictly with a valid JSON object conforming to the required schema. Do not include markdown fences (no ```json). Output pure JSON.
"""

ANALYSIS_PROMPT_TEMPLATE = """Analyze the following malware triage telemetry collected from static PE inspection and behavioral analysis:

### TELEMETRY DATA:
{telemetry_json}

### REQUIRED OUTPUT SCHEMA:
{{
  "threat_level": "CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL",
  "threat_score": 0-100,
  "malware_family": "Suggested family or generic classification (e.g., Trojan.Downloader, InfoStealer, Ransomware)",
  "executive_summary": "High-level summary of the sample's malicious nature, capabilities, and risks.",
  "key_functionality": "Detailed technical breakdown of capabilities observed (e.g. process injection, evasion, C2 communication).",
  "purpose": "Attacker's primary goal (e.g. Initial Access, Credential Access, Command and Control).",
  "persistence": "Detailed description of persistence mechanisms observed (Registry keys, dropped startup items, services).",
  "environment_impact": "Assessment of potential damage to enterprise environment, assets, and data confidentiality.",
  "root_cause": "Likely delivery vector or execution method.",
  "attribution": "Known threat actor or campaign affiliation if matching known signatures, otherwise 'Unattributed'.",
  "mitre_attack": [
    {{
      "technique_id": "TXXXX.XXX",
      "technique_name": "Technique Name",
      "tactic": "Tactic Name",
      "evidence": "Observed API, registry key, or network event supporting this technique"
    }}
  ],
  "key_iocs": {{
    "host_iocs": ["List of file hashes, dropped file paths, registry keys"],
    "network_iocs": ["List of C2 domains, resolved IPs, URLs, User-Agents"]
  }},
  "incident_recommendations": [
    "Actionable containment and eradication recommendations for SOC / DFIR teams"
  ]
}}
"""
