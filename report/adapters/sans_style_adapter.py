"""
0206 - SANS-Style DOCX Report Adapter
Populates findings into user-provided SANS FOR610-style DOCX templates.
Distinguishes evidence states: [OBSERVED], [INFERRED], [NOT_CONFIRMED], [NOT_ANALYZED].
"""
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import docx
from docx.shared import Pt, RGBColor
from report.adapters.base_adapter import BaseReportAdapter
from report.template_validator import TemplateValidator, TemplateValidationError


class SANSStyleReportAdapter(BaseReportAdapter):
    """Fills evidence-grounded findings into a 58-row SANS-style template."""

    def __init__(self, template_path: Path):
        self.template_path = Path(template_path)
        valid, warnings = TemplateValidator.validate_sans_style_template(self.template_path)
        if not valid:
            raise TemplateValidationError("; ".join(warnings))

    def _set_cell_text(self, cell, text: str, font_name: str = "Calibri", font_size_pt: float = 9.5, bold: bool = False):
        cell.text = ""
        lines = text.strip().split("\n")
        for i, line in enumerate(lines):
            p = cell.paragraphs[0] if i == 0 else cell.add_paragraph()
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(1)
            run = p.add_run(line)
            run.font.name = font_name
            run.font.size = Pt(font_size_pt)
            run.bold = bold

    def render(self, session_data: Dict[str, Any], output_path: Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        doc = docx.Document(str(self.template_path))
        table = doc.tables[0]
        rows = table.rows

        manifest = session_data.get("manifest", {})
        assessment = session_data.get("assessment", {})
        raw = session_data.get("raw_telemetry", {})
        static_data = raw.get("static", {})
        behavioral_data = raw.get("behavioral", {})
        code_data = raw.get("code_analysis", {})

        file_info = static_data.get("file_info", {})
        network = behavioral_data.get("network", {})
        host_beh = behavioral_data.get("host_behavior", {})

        def set_kv(r_idx: int, c_idx: int, val: str):
            if r_idx < len(rows) and c_idx < len(rows[r_idx].cells):
                self._set_cell_text(rows[r_idx].cells[c_idx], val)

        def set_data(r_idx: int, val: str):
            if r_idx < len(rows):
                self._set_cell_text(rows[r_idx].cells[0], val)

        # 1. BACKGROUND
        set_kv(1, 2, manifest.get("start_time_utc", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")))
        set_kv(2, 2, f"ANALYSIS-STATION [Case: {manifest.get('case_id', 'N/A')}]")
        set_kv(3, 2, manifest.get("sample_filename", file_info.get("file_name", "Unknown")))
        set_kv(4, 2, file_info.get("file_name", "Local Upload"))
        set_kv(5, 2, f"Compile: {file_info.get('compile_time', 'N/A')}")
        set_kv(6, 2, assessment.get("purpose", "Suspicious artifact submitted for triage"))

        # 2. STATIC ANALYSIS
        set_kv(8, 1, f"{file_info.get('file_size', 0):,} bytes")
        set_kv(9, 1, "Default application icon")
        set_kv(10, 1, "[OBSERVED] Signed" if file_info.get("is_signed") else "[OBSERVED] Unsigned (No digital signature found)")
        
        hashes_str = (
            f"MD5:    {file_info.get('md5', 'N/A')}\n"
            f"SHA1:   {file_info.get('sha1', 'N/A')}\n"
            f"SHA256: {file_info.get('sha256', 'N/A')}"
        )
        set_kv(11, 1, hashes_str)
        set_kv(12, 1, file_info.get("imphash", "N/A"))

        # Row 14: Sections
        sections = static_data.get("sections", [])
        if sections:
            sec_lines = [f"{'Name':<10} {'VirtSize':<10} {'RawSize':<10} {'Entropy':<9} {'Perms':<6} {'MD5 Hash':<32}"]
            sec_lines.append("-" * 80)
            for s in sections:
                rwx_flag = " [RWX!]" if s.get("is_rwx") else ""
                sec_lines.append(f"{s.get('name', ''):<10} {s.get('virtual_size', 0):<10} {s.get('raw_size', 0):<10} {s.get('entropy', 0.0):<9.2f} {s.get('permissions', ''):<6} {s.get('md5', ''):<32}{rwx_flag}")
            set_data(14, "\n".join(sec_lines))
        else:
            set_data(14, "[NOT_ANALYZED] No PE sections parsed.")

        # Row 16: Compile Time
        set_data(16, f"[OBSERVED] TimeDateStamp: {file_info.get('compile_time', 'N/A')}")

        # Row 18: File Properties
        props_text = (
            f"Architecture:    {file_info.get('architecture', 'Unknown')}\n"
            f"Subsystem:       {file_info.get('subsystem', 'Unknown')}\n"
            f"Entry Point:     {file_info.get('entry_point', '0x0')}\n"
            f"Image Base:      {file_info.get('image_base', '0x0')}"
        )
        set_data(18, props_text)

        # Row 20: Strings
        strings_data = static_data.get("strings_analysis", {})
        s_lines = []
        if strings_data.get("urls"):
            s_lines.append("URLs:\n  " + "\n  ".join(strings_data["urls"][:6]))
        if strings_data.get("ips"):
            s_lines.append("IPs:\n  " + "\n  ".join(strings_data["ips"][:6]))
        if strings_data.get("registry_keys"):
            s_lines.append("Registry Keys:\n  " + "\n  ".join(strings_data["registry_keys"][:6]))
        if not s_lines:
            s_lines.append("[OBSERVED] No explicit suspicious network or registry strings filtered.")
        set_data(20, "\n\n".join(s_lines))

        # Row 22: Packed
        p_eval = static_data.get("packer_assessment", {})
        cls = p_eval.get("classification", "NOT_DETECTED")
        p_text = f"STATUS: [{cls}] (Score: {p_eval.get('score', 0)}/100, Confidence: {p_eval.get('confidence', 0.5):.2f})\n"
        if p_eval.get("indicators"):
            p_text += "Indicators:\n  • " + "\n  • ".join(p_eval["indicators"])
        if p_eval.get("caveats"):
            p_text += "\nCaveats:\n  * " + "\n  * ".join(p_eval["caveats"])
        set_data(22, p_text)

        # Row 24: Entropy
        set_data(24, f"Overall Entropy: {file_info.get('overall_entropy', 0.0):.4f}")

        # Row 26: Imports & API Hashing
        imp_lines = []
        api_hashes = static_data.get("api_hashing_matches", [])
        if api_hashes:
            imp_lines.append(f"[OBSERVED_HASH_CONSTANT] Detected {len(api_hashes)} API hash constants:")
            for m in api_hashes[:6]:
                imp_lines.append(f"  Hash {m['hash_hex']} -> {m['api']} ({m['algorithm']}) at offset {m['offset_hex']}")
            imp_lines.append("[NOT_CONFIRMED] Runtime resolution not dynamically verified.\n")

        imports = static_data.get("imports", {})
        for dll, funcs in list(imports.items())[:6]:
            imp_lines.append(f"  {dll.upper()}: {', '.join(funcs[:5])}{'...' if len(funcs)>5 else ''}")
        set_data(26, "\n".join(imp_lines) if imp_lines else "[NOT_ANALYZED] No imports identified.")

        # Row 28: OSINT
        set_data(28, f"Search SHA256: https://www.virustotal.com/gui/file/{file_info.get('sha256', '')}")

        # 3. BEHAVIORAL ANALYSIS
        # Row 31: Dropped files & Registry
        host_lines = []
        dropped = host_beh.get("dropped_files", [])
        if dropped:
            host_lines.append("[OBSERVED] DROPPED FILES:")
            for df in dropped[:5]:
                host_lines.append(f"  [{df.get('process')}] -> {df.get('path')}")
        pers = host_beh.get("persistence_registry", [])
        if pers:
            host_lines.append("[OBSERVED] REGISTRY RUN KEYS:")
            for pr in pers[:5]:
                host_lines.append(f"  {pr.get('key_path')}")
        set_data(31, "\n".join(host_lines) if host_lines else "[NOT_ANALYZED] No host activity recorded.")

        # Row 33: Network
        net_lines = []
        beacons = network.get("c2_beacons", [])
        if beacons:
            net_lines.append("[POTENTIAL_BEACON] SUSPECTED C2 CONNECTIONS:")
            for b in beacons[:4]:
                net_lines.append(f"  {b['destination_ip']}:{b.get('destination_port', 80)} - Score {b.get('beacon_score', 0):.2f} ({b.get('classification')})")
        dns_list = network.get("dns_queries", [])
        if dns_list:
            net_lines.append("[OBSERVED] DNS QUERIES:")
            for d in dns_list[:4]:
                net_lines.append(f"  {d.get('domain')} -> {', '.join(d.get('resolved_ips', []))}")
        set_data(33, "\n".join(net_lines) if net_lines else "[NOT_ANALYZED] No network traffic provided.")

        # Row 35: Memory Analysis
        set_data(35, "[NOT_ANALYZED] Active memory dump analysis not conducted.")

        # Row 37: Network OSINT
        set_data(37, "OSINT queries pending external connectivity.")

        # 4. CODE ANALYSIS
        # Row 40: Static Disassembly
        insns = code_data.get("instructions", [])
        if insns:
            code_text = f"[OBSERVED] Entry-Point Disassembly ({code_data.get('architecture', 'x86')}):\n" + "\n".join(insns[:12])
        else:
            code_text = "[NOT_ANALYZED] Entry-point disassembly not executed or Capstone unavailable."
        set_data(40, code_text)

        # Row 42: Debugging
        set_data(42, f"[NOT_ANALYZED] Dynamic debugging OEP transition not analyzed.")

        # 5. ANALYSIS SUMMARY
        # Row 45: IOCs
        ioc_lines = ["[HOST IOCs]"]
        for h in assessment.get("host_iocs", [])[:6]:
            ioc_lines.append(f"  {h}")
        ioc_lines.append("\n[NETWORK IOCs]")
        for n in assessment.get("network_iocs", [])[:6]:
            ioc_lines.append(f"  {n}")
        set_data(45, "\n".join(ioc_lines))

        set_data(47, assessment.get("key_functionality", "N/A"))
        set_data(49, assessment.get("purpose", "N/A"))
        set_data(51, assessment.get("persistence_assessment", "N/A"))
        set_data(53, assessment.get("environment_impact", "N/A"))
        set_data(55, assessment.get("root_cause", "N/A"))

        # Row 57: Attribution & Recommendations
        attrib_lines = [
            f"Classification: {assessment.get('classification', 'Generic')}",
            f"Threat Level: {assessment.get('threat_level', 'UNKNOWN')} ({assessment.get('threat_score', 0)}/100)\n",
            "RECOMMENDATIONS:"
        ]
        for r in assessment.get("recommendations", []):
            attrib_lines.append(f"  • {r}")
        set_data(57, "\n".join(attrib_lines))

        doc.save(str(output_path))
        return output_path
