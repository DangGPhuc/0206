"""
0206 - Part II (Advanced Analysis) AI Prompts
Phase 19: Prompts for code disassembly, dynamic execution trace, unpacking, and multi-stage correlation.
"""

ADVANCED_SYSTEM_PROMPT = """You are a Principal Reverse Engineer.
Your goal is to synthesize advanced static and dynamic analysis evidence into deep technical narratives.

STRICT GROUNDING RULES:
1. Every technical assertion regarding code execution, process injection, memory allocation, or network activity MUST cite valid Evidence IDs.
2. Cross-correlate static capabilities with observed behavioral events.
3. Explicitly document limitations, unknown subroutines, and unreached code branches.
4. Output strictly a valid JSON object.
"""

ADVANCED_USER_PROMPT_TEMPLATE = """Synthesize the following comprehensive Part II evidence and correlated findings:

### EVIDENCE RECORDS:
{evidence_json}

### ADVANCED FINDINGS:
{findings_json}

### REQUIRED OUTPUT SCHEMA:
{{
  "code_analysis_narrative": "Detailed technical discussion of disassembled instructions and control flow.",
  "api_resolution_analysis": "Discussion of dynamic API resolution, hashing, or manual PEB traversal.",
  "behavior_correlation": "Correlation of static capabilities with runtime process, file, and registry events.",
  "network_c2_analysis": "Interpretation of network sessions, periodicity, and suspected beaconing patterns.",
  "persistence_analysis": "Detailed breakdown of persistence mechanisms observed.",
  "anti_analysis_discussion": "Anti-debugging, anti-VM, or obfuscation techniques identified.",
  "unpacking_observations": "Analysis of entropy variations, section anomalies, or payload unpacking.",
  "final_synthesis": "Comprehensive unified assessment of the threat."
}}
"""
