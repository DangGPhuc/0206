"""
0206 - Static PE Binary Analyzer Module
Extracts comprehensive PE structures, section entropy, strings, Authenticode signatures,
and detects API Hashing constants.
Emits canonical EvidenceRecords into the session EvidenceStore.
"""
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import pefile

from config import (
    MAX_SAMPLE_SIZE, MAX_STRINGS, MAX_STRING_LENGTH,
    ENTROPY_PACKED_THRESHOLD, SUSPICIOUS_SECTIONS,
    SUSPICIOUS_APIS, SUSPICIOUS_STRING_KEYWORDS
)
from core.evidence import EvidenceStore, EvidenceState
from core.manifest import hash_file_streaming
from analyzer.api_hash_db import scan_binary_for_api_hashes


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy for a given byte sequence (0.0 - 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)


def extract_strings(data: bytes, min_len: int = 4, max_strings: int = MAX_STRINGS) -> Dict[str, Any]:
    """
    Extracts ASCII and Unicode (UTF-16LE) strings safely with memory limits
    and categorizes suspicious indicators.
    """
    ascii_pattern = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    unicode_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}')

    all_strings = []
    # Extract ASCII
    for match in ascii_pattern.finditer(data):
        s = match.group(0).decode('ascii', errors='ignore')
        if len(s) > MAX_STRING_LENGTH:
            s = s[:MAX_STRING_LENGTH]
        all_strings.append(s)
        if len(all_strings) >= max_strings:
            break

    # Extract Unicode if under limit
    if len(all_strings) < max_strings:
        for match in unicode_pattern.finditer(data):
            s = match.group(0).decode('utf-16le', errors='ignore')
            if len(s) > MAX_STRING_LENGTH:
                s = s[:MAX_STRING_LENGTH]
            all_strings.append(s)
            if len(all_strings) >= max_strings:
                break

    # Regex filters
    url_re = re.compile(r'https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]+', re.IGNORECASE)
    ip_re = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    reg_re = re.compile(r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|Software\\Microsoft\\[a-zA-Z0-9_\\]+)', re.IGNORECASE)

    joined_text = '\n'.join(all_strings)
    urls = list(set(url_re.findall(joined_text)))
    ips = list(set(ip_re.findall(joined_text)))
    registry_keys = list(set(reg_re.findall(joined_text)))

    suspicious_found = []
    for s in all_strings:
        lower_s = s.lower()
        for kw in SUSPICIOUS_STRING_KEYWORDS:
            if kw.lower() in lower_s and s not in suspicious_found:
                suspicious_found.append(s)
                if len(suspicious_found) >= 50:
                    break

    return {
        "urls": urls[:30],
        "ips": ips[:30],
        "registry_keys": registry_keys[:30],
        "suspicious_commands": suspicious_found[:40],
        "total_strings_count": len(all_strings)
    }


class PEStaticAnalyzer:
    """Performs full static inspection of Windows PE binaries with evidence grounding."""

    def __init__(self, file_path: Path, evidence_store: Optional[EvidenceStore] = None):
        self.file_path = Path(file_path)
        self.evidence_store = evidence_store if evidence_store is not None else EvidenceStore()
        self.raw_data = b""
        self.pe: Optional[pefile.PE] = None
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def analyze(self) -> Dict[str, Any]:
        """Executes full static analysis and emits EvidenceRecords."""
        if not self.file_path.exists():
            return {"error": f"File not found: {self.file_path}"}

        # Validate file size limits
        file_size = self.file_path.stat().st_size
        if file_size > MAX_SAMPLE_SIZE:
            self.errors.append(f"Sample size {file_size:,} bytes exceeds limit of {MAX_SAMPLE_SIZE:,} bytes")
            return {"error": self.errors[-1]}

        # Compute streaming hashes
        hashes = hash_file_streaming(self.file_path)

        # Read binary data safely
        try:
            with open(self.file_path, "rb") as f:
                self.raw_data = f.read()
        except Exception as e:
            return {"error": f"Failed to read file: {e}"}

        overall_entropy = calculate_shannon_entropy(self.raw_data)
        artifact_name = self.file_path.name

        # Register foundational file evidence
        self.evidence_store.create(artifact_name, "FILE_METADATA", "sha256", hashes["sha256"], "PEStaticAnalyzer")
        self.evidence_store.create(artifact_name, "FILE_METADATA", "file_size", file_size, "PEStaticAnalyzer")
        self.evidence_store.create(artifact_name, "FILE_METADATA", "overall_entropy", overall_entropy, "PEStaticAnalyzer")

        telemetry: Dict[str, Any] = {
            "file_info": {
                "file_name": artifact_name,
                "file_path": str(self.file_path.resolve()),
                "file_size": file_size,
                "md5": hashes["md5"],
                "sha1": hashes["sha1"],
                "sha256": hashes["sha256"],
                "overall_entropy": overall_entropy,
                "is_pe": False,
                "is_signed": False,
                "imphash": "N/A",
                "compile_time": "N/A",
                "architecture": "Unknown",
                "subsystem": "Unknown",
                "entry_point": "0x0",
                "image_base": "0x0"
            },
            "sections": [],
            "imports": {},
            "exports": [],
            "detected_capabilities": {},
            "api_hashing_matches": [],
            "packer_assessment": {
                "classification": "NOT_DETECTED",
                "score": 0,
                "confidence": 0.5,
                "indicators": [],
                "caveats": []
            },
            "strings_analysis": {},
            "anomalies": []
        }

        # Parse PE
        try:
            self.pe = pefile.PE(data=self.raw_data, fast_load=False)
            telemetry["file_info"]["is_pe"] = True
            self.evidence_store.create(artifact_name, "PE_HEADER", "is_pe", True, "PEStaticAnalyzer")
        except pefile.PEFormatError as e:
            self.warnings.append(f"Not a valid PE file or corrupted header: {e}")
            telemetry["strings_analysis"] = extract_strings(self.raw_data)
            telemetry["warnings"] = self.warnings
            return telemetry
        except Exception as e:
            self.errors.append(f"PE parsing error: {e}")
            telemetry["strings_analysis"] = extract_strings(self.raw_data)
            telemetry["errors"] = self.errors
            return telemetry

        # Headers & Architecture
        try:
            machine = self.pe.FILE_HEADER.Machine
            if machine == 0x014c:
                telemetry["file_info"]["architecture"] = "32-bit (x86)"
            elif machine == 0x8664:
                telemetry["file_info"]["architecture"] = "64-bit (x64)"
            else:
                telemetry["file_info"]["architecture"] = f"Other (0x{machine:04X})"

            self.evidence_store.create(artifact_name, "PE_HEADER", "architecture", telemetry["file_info"]["architecture"], "PEStaticAnalyzer")

            subsystem_val = getattr(self.pe.OPTIONAL_HEADER, "Subsystem", 0)
            subsystems = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI (Console)", 7: "POSIX"}
            telemetry["file_info"]["subsystem"] = subsystems.get(subsystem_val, f"Unknown ({subsystem_val})")

            ep = getattr(self.pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)
            ib = getattr(self.pe.OPTIONAL_HEADER, "ImageBase", 0)
            telemetry["file_info"]["entry_point"] = f"0x{ep:08X}"
            telemetry["file_info"]["image_base"] = f"0x{ib:08X}"
            self.evidence_store.create(artifact_name, "PE_HEADER", "entry_point", f"0x{ep:08X}", "PEStaticAnalyzer")

            # Timestamp
            timestamp = self.pe.FILE_HEADER.TimeDateStamp
            try:
                dt = datetime.fromtimestamp(timestamp, timezone.utc)
                telemetry["file_info"]["compile_time"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                if dt.year < 2000 or dt.year > datetime.now().year + 1:
                    telemetry["anomalies"].append(f"Suspicious compile timestamp: {telemetry['file_info']['compile_time']} (Possible Timestomping)")
            except Exception:
                telemetry["file_info"]["compile_time"] = f"Invalid timestamp (0x{timestamp:08X})"
                telemetry["anomalies"].append("Corrupted or invalid TimeDateStamp")

            # Imphash
            try:
                imphash = self.pe.get_imphash()
                if imphash:
                    telemetry["file_info"]["imphash"] = imphash
                    self.evidence_store.create(artifact_name, "PE_IMPORT", "imphash", imphash, "PEStaticAnalyzer")
            except Exception:
                telemetry["file_info"]["imphash"] = "N/A"

            # Authenticode
            sec_entry = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            is_signed = bool(sec_entry.VirtualAddress != 0 and sec_entry.Size > 0)
            telemetry["file_info"]["is_signed"] = is_signed
            self.evidence_store.create(artifact_name, "AUTHENTICODE", "is_signed", is_signed, "PEStaticAnalyzer")

        except Exception as e:
            self.errors.append(f"Error parsing headers: {e}")

        # Section Analysis & Packer Indicators
        packer_score = 0
        packer_indicators = []
        packer_caveats = []

        try:
            for section in self.pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                sec_data = section.get_data()
                sec_entropy = calculate_shannon_entropy(sec_data)

                chars = section.Characteristics
                can_read = bool(chars & 0x40000000)
                can_write = bool(chars & 0x80000000)
                can_exec = bool(chars & 0x20000000)

                perm_str = ("R" if can_read else "") + ("W" if can_write else "") + ("X" if can_exec else "")
                is_rwx = (can_read and can_write and can_exec)

                sec_info = {
                    "name": sec_name,
                    "virtual_address": f"0x{section.VirtualAddress:08X}",
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": sec_entropy,
                    "permissions": perm_str,
                    "is_rwx": is_rwx
                }
                telemetry["sections"].append(sec_info)

                # Record section evidence
                self.evidence_store.create(
                    artifact_name, "PE_SECTION", "section_entropy", sec_entropy, "PEStaticAnalyzer",
                    provenance={"section_name": sec_name, "raw_size": section.SizeOfRawData}
                )

                if is_rwx:
                    telemetry["anomalies"].append(f"Section '{sec_name}' has RWX permissions")
                    self.evidence_store.create(
                        artifact_name, "PE_SECTION", "section_is_rwx", True, "PEStaticAnalyzer",
                        provenance={"section_name": sec_name}
                    )
                    packer_score += 25
                    packer_indicators.append(f"Section '{sec_name}' has RWX memory permissions")

                # Section entropy evaluation
                if sec_entropy >= 7.2:
                    packer_score += 30
                    packer_indicators.append(f"High Shannon entropy in section '{sec_name}' ({sec_entropy:.2f})")
                elif sec_entropy >= ENTROPY_PACKED_THRESHOLD:
                    packer_score += 15
                    packer_indicators.append(f"Elevated Shannon entropy in section '{sec_name}' ({sec_entropy:.2f})")

                # Size discrepancy (Raw vs Virtual)
                if section.Misc_VirtualSize > 0 and section.SizeOfRawData == 0:
                    packer_score += 30
                    packer_indicators.append(f"Section '{sec_name}' has 0 raw size but virtual size {section.Misc_VirtualSize} (uninitialized unpacking buffer)")
                elif section.Misc_VirtualSize > section.SizeOfRawData * 3 and section.SizeOfRawData > 0:
                    packer_score += 20
                    packer_indicators.append(f"Section '{sec_name}' virtual size is >3x larger than raw size")

                # Known packer section name
                if any(susp in sec_name.lower() for susp in SUSPICIOUS_SECTIONS):
                    packer_score += 35
                    packer_indicators.append(f"Known packer/stub section name pattern: '{sec_name}'")

        except Exception as e:
            self.errors.append(f"Error reading sections: {e}")

        # Imports & Capability Detection
        total_import_count = 0
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    imports_list = []
                    for imp in entry.imports:
                        func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal({imp.ordinal})"
                        imports_list.append(func_name)
                        total_import_count += 1

                        # Match capabilities
                        for cap_name, cap_data in SUSPICIOUS_APIS.items():
                            if func_name in cap_data["apis"]:
                                if cap_name not in telemetry["detected_capabilities"]:
                                    telemetry["detected_capabilities"][cap_name] = []
                                if func_name not in telemetry["detected_capabilities"][cap_name]:
                                    telemetry["detected_capabilities"][cap_name].append(func_name)

                                # Register evidence
                                if "Process Injection" in cap_name:
                                    self.evidence_store.create(artifact_name, "PE_IMPORT", "imported_api_injection", func_name, "PEStaticAnalyzer")
                                elif "Persistence" in cap_name:
                                    self.evidence_store.create(artifact_name, "PE_IMPORT", "imported_api_persistence", func_name, "PEStaticAnalyzer")
                                elif "Network" in cap_name:
                                    self.evidence_store.create(artifact_name, "PE_IMPORT", "imported_api_network", func_name, "PEStaticAnalyzer")

                    telemetry["imports"][dll_name] = imports_list
            else:
                telemetry["imports"] = {}
                telemetry["anomalies"].append("No Import Directory found (Executable may be packed, shellcode, or heavily obfuscated)")
                packer_score += 30
                packer_indicators.append("Missing Import Directory")
        except Exception as e:
            self.errors.append(f"Error reading imports: {e}")

        if total_import_count < 5 and telemetry["file_info"]["is_pe"]:
            packer_score += 20
            packer_indicators.append(f"Unusually low import count ({total_import_count} APIs)")

        # Overall file entropy
        if overall_entropy >= 7.2:
            packer_score += 20
            packer_indicators.append(f"Overall file entropy is very high ({overall_entropy:.2f})")
            packer_caveats.append("High entropy may also indicate compressed media/resources rather than executable packing.")

        # Multi-heuristic Packer Assessment
        packer_score = min(100, packer_score)
        if packer_score >= 70:
            packer_class = "LIKELY_PACKED"
        elif packer_score >= 40:
            packer_class = "POSSIBLE_PACKING"
        else:
            packer_class = "NOT_DETECTED"

        telemetry["packer_assessment"] = {
            "classification": packer_class,
            "score": packer_score,
            "confidence": min(0.95, 0.4 + (packer_score / 200)),
            "indicators": packer_indicators,
            "caveats": packer_caveats
        }
        # Backward compatibility field
        telemetry["packed_analysis"] = {
            "is_packed": packer_class in ("POSSIBLE_PACKING", "LIKELY_PACKED"),
            "reasons": packer_indicators
        }
        self.evidence_store.create(artifact_name, "PACKER_HEURISTICS", "packer_assessment", telemetry["packer_assessment"], "PEStaticAnalyzer")

        # Scan for API Hashing constants
        try:
            hash_matches = scan_binary_for_api_hashes(self.raw_data)
            telemetry["api_hashing_matches"] = hash_matches
            for m in hash_matches:
                self.evidence_store.create(
                    artifact_name, "BINARY_DATA", "api_hash_match", m, "PEStaticAnalyzer",
                    provenance={"offset": m.get("offset_hex"), "algorithm": m.get("algorithm")}
                )
            if hash_matches:
                telemetry["anomalies"].append(
                    f"Detected {len(hash_matches)} API Hashing constant(s) indicating potential dynamic API resolution"
                )
        except Exception as e:
            self.errors.append(f"Error during API hash scan: {e}")

        # Strings
        try:
            telemetry["strings_analysis"] = extract_strings(self.raw_data)
        except Exception as e:
            self.errors.append(f"Error extracting strings: {e}")

        telemetry["errors"] = self.errors
        telemetry["warnings"] = self.warnings
        return telemetry
