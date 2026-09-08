"""
Static PE Binary Analyzer Module
Extracts comprehensive PE structures, hashes, section entropy, strings,
Authenticode signatures, and detects API Hashing constants.
"""
import math
import re
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import pefile

from config import ENTROPY_PACKED_THRESHOLD, SUSPICIOUS_SECTIONS, SUSPICIOUS_APIS, SUSPICIOUS_STRING_KEYWORDS
from analyzer.api_hash_db import scan_binary_for_api_hashes


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy for given byte sequence (0.0 - 8.0)."""
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


def extract_strings(data: bytes, min_len: int = 4) -> Dict[str, List[str]]:
    """
    Extracts ASCII and Unicode (UTF-16LE) strings and filters them
    by suspicious indicators (URLs, IPs, Registry, Commands).
    """
    ascii_pattern = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    unicode_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}')

    raw_ascii = [match.group(0).decode('ascii', errors='ignore') for match in ascii_pattern.finditer(data)]
    raw_unicode = [match.group(0).decode('utf-16le', errors='ignore') for match in unicode_pattern.finditer(data)]
    all_strings = raw_ascii + raw_unicode

    # Regex filters
    url_re = re.compile(r'https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]+', re.IGNORECASE)
    ip_re = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    reg_re = re.compile(r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|Software\\Microsoft\\[a-zA-Z0-9_\\]+)', re.IGNORECASE)

    urls = list(set(url_re.findall('\n'.join(all_strings))))
    ips = list(set(ip_re.findall('\n'.join(all_strings))))
    # Filter out common false positives like 0.0.0.0 or 127.0.0.1 if desired, but keep for completeness
    registry_keys = list(set(reg_re.findall('\n'.join(all_strings))))

    # Suspicious keywords
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
    """Performs full static inspection of Windows PE binaries."""

    def __init__(self, file_path: Path):
        self.file_path = Path(file_path)
        self.raw_data = b""
        self.pe: Optional[pefile.PE] = None
        self.errors: List[str] = []

    def analyze(self) -> Dict[str, Any]:
        """Executes full static analysis and returns structured telemetry."""
        if not self.file_path.exists():
            return {"error": f"File not found: {self.file_path}"}

        try:
            with open(self.file_path, "rb") as f:
                self.raw_data = f.read()
        except Exception as e:
            return {"error": f"Failed to read file: {e}"}

        file_size = len(self.raw_data)
        md5_hash = hashlib.md5(self.raw_data).hexdigest()
        sha1_hash = hashlib.sha1(self.raw_data).hexdigest()
        sha256_hash = hashlib.sha256(self.raw_data).hexdigest()
        overall_entropy = calculate_shannon_entropy(self.raw_data)

        # Base telemetry structure
        telemetry: Dict[str, Any] = {
            "file_info": {
                "file_name": self.file_path.name,
                "file_path": str(self.file_path.resolve()),
                "file_size": file_size,
                "md5": md5_hash,
                "sha1": sha1_hash,
                "sha256": sha256_hash,
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
            "packed_analysis": {
                "is_packed": False,
                "reasons": []
            },
            "strings_analysis": {},
            "anomalies": []
        }

        # Attempt PE parsing
        try:
            self.pe = pefile.PE(data=self.raw_data, fast_load=False)
            telemetry["file_info"]["is_pe"] = True
        except pefile.PEFormatError as e:
            self.errors.append(f"Not a valid PE file or corrupted header: {e}")
            telemetry["strings_analysis"] = extract_strings(self.raw_data)
            telemetry["errors"] = self.errors
            return telemetry
        except Exception as e:
            self.errors.append(f"PE parsing error: {e}")
            telemetry["strings_analysis"] = extract_strings(self.raw_data)
            telemetry["errors"] = self.errors
            return telemetry

        # File Properties & Header details
        try:
            # Architecture
            machine = self.pe.FILE_HEADER.Machine
            if machine == 0x014c:
                telemetry["file_info"]["architecture"] = "32-bit (x86)"
            elif machine == 0x8664:
                telemetry["file_info"]["architecture"] = "64-bit (x64)"
            else:
                telemetry["file_info"]["architecture"] = f"Other (0x{machine:04X})"

            # Subsystem
            subsystem_val = getattr(self.pe.OPTIONAL_HEADER, "Subsystem", 0)
            subsystems = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI (Console)", 7: "POSIX"}
            telemetry["file_info"]["subsystem"] = subsystems.get(subsystem_val, f"Unknown ({subsystem_val})")

            # Entry Point & Image Base
            ep = getattr(self.pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)
            ib = getattr(self.pe.OPTIONAL_HEADER, "ImageBase", 0)
            telemetry["file_info"]["entry_point"] = f"0x{ep:08X}"
            telemetry["file_info"]["image_base"] = f"0x{ib:08X}"

            # Compile Timestamp
            timestamp = self.pe.FILE_HEADER.TimeDateStamp
            try:
                dt = datetime.fromtimestamp(timestamp, timezone.utc)
                telemetry["file_info"]["compile_time"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                # Timestomping heuristic
                if dt.year < 2000 or dt.year > datetime.now().year + 1:
                    telemetry["anomalies"].append(f"Suspicious compile timestamp: {telemetry['file_info']['compile_time']} (Possible Timestomping)")
            except Exception:
                telemetry["file_info"]["compile_time"] = f"Invalid timestamp (0x{timestamp:08X})"
                telemetry["anomalies"].append("Corrupted or invalid TimeDateStamp")

            # Imphash
            try:
                imphash = self.pe.get_imphash()
                telemetry["file_info"]["imphash"] = imphash if imphash else "N/A"
            except Exception:
                telemetry["file_info"]["imphash"] = "Error computing imphash"

            # Authenticode Signature check
            sec_entry = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            if sec_entry.VirtualAddress != 0 and sec_entry.Size > 0:
                telemetry["file_info"]["is_signed"] = True
                telemetry["file_info"]["signature_size"] = sec_entry.Size
            else:
                telemetry["file_info"]["is_signed"] = False

        except Exception as e:
            self.errors.append(f"Error parsing headers: {e}")

        # Sections analysis
        rwx_sections_found = False
        packed_reasons = []
        try:
            for section in self.pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                sec_entropy = calculate_shannon_entropy(section.get_data())
                sec_md5 = hashlib.md5(section.get_data()).hexdigest()
                
                # Check permissions
                chars = section.Characteristics
                can_read = bool(chars & 0x40000000)
                can_write = bool(chars & 0x80000000)
                can_exec = bool(chars & 0x20000000)

                perm_str = ""
                if can_read: perm_str += "R"
                if can_write: perm_str += "W"
                if can_exec: perm_str += "X"

                is_rwx = (can_read and can_write and can_exec)
                if is_rwx:
                    rwx_sections_found = True
                    telemetry["anomalies"].append(f"Section '{sec_name}' has RWX (Read-Write-Execute) permissions - High risk for code injection / unpacking")

                if sec_entropy >= ENTROPY_PACKED_THRESHOLD:
                    packed_reasons.append(f"High entropy in section '{sec_name}' ({sec_entropy})")

                # Check suspicious name
                if any(susp.lower() in sec_name.lower() for susp in SUSPICIOUS_SECTIONS):
                    packed_reasons.append(f"Known packer/suspicious section name: '{sec_name}'")

                telemetry["sections"].append({
                    "name": sec_name,
                    "virtual_address": f"0x{section.VirtualAddress:08X}",
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": sec_entropy,
                    "md5": sec_md5,
                    "permissions": perm_str,
                    "is_rwx": is_rwx
                })
        except Exception as e:
            self.errors.append(f"Error reading sections: {e}")

        # Packed Evaluation
        if overall_entropy >= ENTROPY_PACKED_THRESHOLD:
            packed_reasons.append(f"High overall file entropy ({overall_entropy})")
        
        telemetry["packed_analysis"]["is_packed"] = bool(packed_reasons)
        telemetry["packed_analysis"]["reasons"] = packed_reasons

        # Imports & Suspicious API mapping
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

                        # Match against suspicious capabilities
                        for cap_name, cap_data in SUSPICIOUS_APIS.items():
                            if func_name in cap_data["apis"]:
                                if cap_name not in telemetry["detected_capabilities"]:
                                    telemetry["detected_capabilities"][cap_name] = []
                                if func_name not in telemetry["detected_capabilities"][cap_name]:
                                    telemetry["detected_capabilities"][cap_name].append(func_name)

                    telemetry["imports"][dll_name] = imports_list
            else:
                telemetry["imports"] = {}
                telemetry["anomalies"].append("No Import Directory found (Executable may be packed, shellcode, or heavily obfuscated)")
        except Exception as e:
            self.errors.append(f"Error reading imports: {e}")

        if total_import_count < 5 and telemetry["file_info"]["is_pe"]:
            telemetry["packed_analysis"]["reasons"].append(f"Unusually low import count ({total_import_count} APIs), common in packed binaries")
            telemetry["packed_analysis"]["is_packed"] = True

        # Exports
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exp_name = exp.name.decode('utf-8', errors='ignore') if exp.name else f"Ordinal({exp.ordinal})"
                    telemetry["exports"].append({
                        "name": exp_name,
                        "ordinal": exp.ordinal,
                        "address": f"0x{exp.address:08X}"
                    })
        except Exception as e:
            self.errors.append(f"Error reading exports: {e}")

        # Scan for API Hashing constants (Maldev Academy module)
        try:
            hash_matches = scan_binary_for_api_hashes(self.raw_data)
            telemetry["api_hashing_matches"] = hash_matches
            if hash_matches:
                telemetry["anomalies"].append(
                    f"Detected {len(hash_matches)} API Hashing constant(s) indicating hidden dynamic API resolution"
                )
        except Exception as e:
            self.errors.append(f"Error during API hash scan: {e}")

        # Extract & Filter Strings
        try:
            telemetry["strings_analysis"] = extract_strings(self.raw_data)
        except Exception as e:
            self.errors.append(f"Error extracting strings: {e}")

        telemetry["errors"] = self.errors
        return telemetry
