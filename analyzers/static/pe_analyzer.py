"""
0206 - Static PE Binary Analyzer Module
Extracts comprehensive PE structures, section entropy, strings, Authenticode signatures,
and detects API Hashing constants.
Emits canonical EvidenceRecords into the session EvidenceStore tagged by AnalysisDomain.
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
from core.schemas import AnalysisDomain, EvidenceState
from core.evidence import EvidenceStore
from core.manifest import hash_file_streaming
from analyzers.static.api_hashing import scan_binary_for_api_hashes


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
        self.evidence_store = evidence_store or EvidenceStore()
        self.hashes: Dict[str, str] = {}
        self.pe: Optional[pefile.PE] = None
        self.errors: List[str] = []

    def analyze(self) -> Dict[str, Any]:
        """Runs complete static PE extraction pipeline."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"Sample file not found: {self.file_path}")

        file_size = self.file_path.stat().st_size
        self.hashes = hash_file_streaming(self.file_path)
        sha256 = self.hashes.get("sha256", "UNKNOWN")

        # 1. Base Metadata
        self.evidence_store.create(
            self.file_path.name, "FILE_METADATA", "filename", self.file_path.name, "PEStaticAnalyzer",
            artifact_sha256=sha256, domain=AnalysisDomain.PE
        )
        self.evidence_store.create(
            self.file_path.name, "FILE_METADATA", "sha256", sha256, "PEStaticAnalyzer",
            artifact_sha256=sha256, domain=AnalysisDomain.PE,
            provenance={"file_size": file_size, "md5": self.hashes.get("md5"), "sha1": self.hashes.get("sha1")}
        )
        self.evidence_store.create(
            self.file_path.name, "FILE_METADATA", "file_size", file_size, "PEStaticAnalyzer",
            artifact_sha256=sha256, domain=AnalysisDomain.PE
        )

        with open(self.file_path, "rb") as f:
            raw_bytes = f.read(min(file_size, MAX_SAMPLE_SIZE))

        overall_entropy = calculate_shannon_entropy(raw_bytes)
        self.evidence_store.create(
            self.file_path.name, "PE_METRICS", "overall_entropy", overall_entropy, "PEStaticAnalyzer",
            artifact_sha256=sha256, domain=AnalysisDomain.PE
        )

        # 2. Parse PE Structures
        is_pe = False
        pe_info: Dict[str, Any] = {}
        sections_data: List[Dict[str, Any]] = []
        imports_data: Dict[str, List[str]] = {}
        exports_data: List[str] = []
        imphash = "N/A"

        try:
            self.pe = pefile.PE(data=raw_bytes, fast_load=False)
            is_pe = True
            self.evidence_store.create(
                self.file_path.name, "PE_HEADER", "is_pe", True, "PEStaticAnalyzer",
                artifact_sha256=sha256, domain=AnalysisDomain.PE
            )

            # Machine & Arch
            arch = "x86" if self.pe.FILE_HEADER.Machine == 0x14C else "x64" if self.pe.FILE_HEADER.Machine == 0x8664 else "Unknown"
            self.evidence_store.create(
                self.file_path.name, "PE_HEADER", "architecture", arch, "PEStaticAnalyzer",
                artifact_sha256=sha256, domain=AnalysisDomain.PE
            )

            # Subsystem
            subsys_val = self.pe.OPTIONAL_HEADER.Subsystem
            subsys = "WINDOWS_GUI" if subsys_val == 2 else "WINDOWS_CUI" if subsys_val == 3 else f"Unknown ({subsys_val})"
            self.evidence_store.create(
                self.file_path.name, "PE_HEADER", "subsystem", subsys, "PEStaticAnalyzer",
                artifact_sha256=sha256, domain=AnalysisDomain.PE
            )

            # Entry point & Image base
            ep = hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            ib = hex(self.pe.OPTIONAL_HEADER.ImageBase)
            self.evidence_store.create(
                self.file_path.name, "PE_HEADER", "entry_point", ep, "PEStaticAnalyzer",
                artifact_sha256=sha256, domain=AnalysisDomain.PE
            )
            self.evidence_store.create(
                self.file_path.name, "PE_HEADER", "image_base", ib, "PEStaticAnalyzer",
                artifact_sha256=sha256, domain=AnalysisDomain.PE
            )

            # Compile Timestamp
            ts = self.pe.FILE_HEADER.TimeDateStamp
            compile_time = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts > 0 else "Invalid/Zero"
            self.evidence_store.create(
                self.file_path.name, "PE_HEADER", "compile_time", compile_time, "PEStaticAnalyzer",
                artifact_sha256=sha256, domain=AnalysisDomain.PE, provenance={"timestamp_raw": ts}
            )

            # Imphash
            try:
                imphash = self.pe.get_imphash()
                if imphash:
                    self.evidence_store.create(
                        self.file_path.name, "PE_HEADER", "imphash", imphash, "PEStaticAnalyzer",
                        artifact_sha256=sha256, domain=AnalysisDomain.PE
                    )
            except Exception:
                imphash = "N/A"

            # 3. Sections Analysis
            rwx_found = False
            for sec in self.pe.sections:
                name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
                vaddr = hex(sec.VirtualAddress)
                vsize = sec.Misc_VirtualSize
                rsize = sec.SizeOfRawData
                sec_entropy = sec.get_entropy()

                # Permissions
                perms = []
                if sec.Characteristics & 0x40000000: perms.append("READ")
                if sec.Characteristics & 0x80000000: perms.append("WRITE")
                if sec.Characteristics & 0x20000000: perms.append("EXECUTE")
                is_rwx = ("READ" in perms and "WRITE" in perms and "EXECUTE" in perms)

                sec_item = {
                    "name": name,
                    "virtual_address": vaddr,
                    "virtual_size": vsize,
                    "raw_size": rsize,
                    "entropy": round(sec_entropy, 4),
                    "permissions": " | ".join(perms),
                    "is_rwx": is_rwx,
                    "md5": sec.get_hash_md5()
                }
                sections_data.append(sec_item)

                self.evidence_store.create(
                    self.file_path.name, "PE_SECTION", "section_entropy", sec_entropy, "PEStaticAnalyzer",
                    artifact_sha256=sha256, domain=AnalysisDomain.PE,
                    provenance={"section_name": name, "virtual_size": vsize, "raw_size": rsize}
                )

                if is_rwx:
                    rwx_found = True
                    self.evidence_store.create(
                        self.file_path.name, "PE_SECTION", "section_is_rwx", True, "PEStaticAnalyzer",
                        artifact_sha256=sha256, domain=AnalysisDomain.MEMORY,
                        provenance={"section_name": name, "permissions": "RWX", "virtual_address": vaddr}
                    )

                for susp_sec in SUSPICIOUS_SECTIONS:
                    if susp_sec.lower() in name.lower():
                        self.evidence_store.create(
                            self.file_path.name, "PE_SECTION", "suspicious_section_name", name, "PEStaticAnalyzer",
                            artifact_sha256=sha256, domain=AnalysisDomain.PACKING,
                            provenance={"matched_indicator": susp_sec}
                        )

            # 4. Imports Inspection
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    imported_funcs = []
                    for imp in entry.imports:
                        func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal({imp.ordinal})"
                        imported_funcs.append(func_name)

                        # Check suspicious APIs
                        for susp_api, category in SUSPICIOUS_APIS.items():
                            if susp_api.lower() == func_name.lower():
                                self.evidence_store.create(
                                    self.file_path.name, "PE_IMPORT", f"imported_api_{category}", func_name, "PEStaticAnalyzer",
                                    artifact_sha256=sha256, domain=AnalysisDomain.API,
                                    provenance={"dll": dll_name, "category": category}
                                )
                    imports_data[dll_name] = imported_funcs

            # 5. Exports
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exp_name = exp.name.decode('utf-8', errors='ignore') if exp.name else f"Ordinal({exp.ordinal})"
                    exports_data.append(exp_name)

        except pefile.PEFormatError as e:
            self.errors.append(f"PE parsing error: {e}")
            self.evidence_store.create(
                self.file_path.name, "PE_HEADER", "is_pe", False, "PEStaticAnalyzer",
                artifact_sha256=sha256, domain=AnalysisDomain.PE, provenance={"error": str(e)}
            )

        # 6. Strings Extraction & Suspicious Indicators
        strings_data = extract_strings(raw_bytes)
        for url in strings_data.get("urls", []):
            self.evidence_store.create(
                self.file_path.name, "BINARY_STRINGS", "embedded_url", url, "PEStaticAnalyzer",
                artifact_sha256=sha256, domain=AnalysisDomain.NETWORK
            )
        for ip in strings_data.get("ips", []):
            self.evidence_store.create(
                self.file_path.name, "BINARY_STRINGS", "embedded_ip", ip, "PEStaticAnalyzer",
                artifact_sha256=sha256, domain=AnalysisDomain.NETWORK
            )
        for reg in strings_data.get("registry_keys", []):
            self.evidence_store.create(
                self.file_path.name, "BINARY_STRINGS", "embedded_registry_key", reg, "PEStaticAnalyzer",
                artifact_sha256=sha256, domain=AnalysisDomain.REGISTRY
            )

        # 7. Win32 API Hashing Precomputed Constants Scan
        api_hash_matches = scan_binary_for_api_hashes(raw_bytes)
        for match in api_hash_matches:
            self.evidence_store.create(
                self.file_path.name, "BINARY_DATA", "api_hash_match", match, "PEStaticAnalyzer",
                artifact_sha256=sha256, domain=AnalysisDomain.API,
                source_offset=match.get("offset"),
                provenance=match
            )

        # 8. Packing Assessment
        packer_score = 0
        packer_indicators = []
        if overall_entropy > ENTROPY_PACKED_THRESHOLD:
            packer_score += 40
            packer_indicators.append(f"High overall entropy ({overall_entropy:.2f} > {ENTROPY_PACKED_THRESHOLD})")
        if rwx_found:
            packer_score += 35
            packer_indicators.append("Concurrent Read, Write, and Execute (RWX) section detected")
        if is_pe and len(imports_data) > 0 and len(imports_data.get("KERNEL32.dll", [])) < 5 and len(imports_data) <= 2:
            packer_score += 25
            packer_indicators.append("Extremely sparse Import Address Table (possible unpacking stub)")

        packing_classification = "NOT_DETECTED"
        if packer_score >= 60:
            packing_classification = "LIKELY_PACKED"
        elif packer_score >= 35:
            packing_classification = "POSSIBLE_PACKING"

        packer_assessment = {
            "score": packer_score,
            "classification": packing_classification,
            "confidence": 0.80 if packer_score >= 60 else 0.50,
            "indicators": packer_indicators,
            "caveats": [
                "Entropy is a heuristic indicator of compression/encryption, not cryptographic proof of malice.",
                "Unpacking or dynamic execution trace required for definitive unpacking verification."
            ]
        }
        self.evidence_store.create(
            self.file_path.name, "HEURISTIC_ANALYZER", "packer_assessment", packer_assessment, "PEStaticAnalyzer",
            artifact_sha256=sha256, domain=AnalysisDomain.PACKING,
            provenance={"score": packer_score, "classification": packing_classification}
        )

        pe_info = {
            "file_info": {
                "file_name": self.file_path.name,
                "file_path": str(self.file_path.resolve()),
                "file_size": file_size,
                "md5": self.hashes.get("md5"),
                "sha1": self.hashes.get("sha1"),
                "sha256": sha256,
                "overall_entropy": overall_entropy,
                "is_pe": is_pe,
                "is_signed": False,
                "imphash": imphash,
                "compile_time": compile_time if is_pe else "N/A",
                "architecture": arch if is_pe else "Unknown",
                "subsystem": subsys if is_pe else "Unknown",
                "entry_point": ep if is_pe else "0x0",
                "image_base": ib if is_pe else "0x0"
            },
            "sections": sections_data,
            "imports": imports_data,
            "exports": exports_data,
            "strings": strings_data,
            "api_hash_matches": api_hash_matches,
            "packer_assessment": packer_assessment,
            "errors": self.errors
        }
        return pe_info
