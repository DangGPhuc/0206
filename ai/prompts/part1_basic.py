"""
0206 - Part I (Basic Analysis) AI Prompts
Phase 18: Prompts for basic triage, sample identification, reputation, and initial indicators.
"""

BASIC_SYSTEM_PROMPT = """You are an expert Malware Triage Analyst.
Your goal is to synthesize the preliminary triage evidence into a concise executive summary and identify initial analytical priorities.

STRICT GROUNDING RULES:
1. Every claim must cite evidence IDs (e.g. E-0001).
2. Do NOT invent indicators, file hashes, IPs, domains, or registry keys.
3. If an aspect was not analyzed or not observed, state "NOT_ANALYZED" or "NOT_CONFIRMED".
4. Output strictly a valid JSON object.
"""

BASIC_USER_PROMPT_TEMPLATE = """Analyze the following Part I basic triage evidence and findings:

### EVIDENCE RECORDS:
{evidence_json}

### DETERMINISTIC FINDINGS:
{findings_json}

### REQUIRED OUTPUT SCHEMA:
{{
  "executive_summary": "Concise high-level summary of sample nature and suspicious indicators.",
  "key_functionality": "Observed capabilities supported by evidence.",
  "purpose": "Suspected primary intent based on evidence.",
  "persistence": "Persistence observations citing evidence IDs, or 'NOT_CONFIRMED'.",
  "environment_impact": "Assessed operational risk.",
  "root_cause": "Suspected delivery or file type context.",
  "analytical_priorities": [
    "Priority areas for deeper investigation (e.g., specific subroutines, domains, strings)"
  ],
  "mitre_attack": [
    {{
      "technique_id": "TXXXX",
      "technique_name": "Name",
      "tactic": "Tactic",
      "evidence_ids": ["E-XXXX"]
    }}
  ],
  "incident_recommendations": [
    "Recommended containment or blocking actions"
  ]
}}
"""
