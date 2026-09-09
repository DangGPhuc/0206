"""
0206 - Resource Policy & Safety Enforcement
Defines resource thresholds to prevent memory exhaustion, DoS, and runaway processing.
All analyzers and the orchestrator consult this policy.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Optional

from config import (
    MAX_SAMPLE_SIZE,
    MAX_PCAP_SIZE,
    MAX_PACKETS,
    MAX_TRACKED_CONNECTIONS,
    MAX_TIMESTAMPS_PER_CONNECTION,
    MAX_STRINGS,
    MAX_STRING_LENGTH,
    MAX_LOG_ROWS,
    MAX_REGSHOT_SIZE,
    MAX_REGSHOT_LINES,
    MAX_REPORT_SIZE,
    ANALYSIS_TIMEOUT,
    ADAPTER_TIMEOUT,
    MAX_STDOUT_BYTES,
    MAX_STDERR_BYTES
)


@dataclass
class ResourcePolicy:
    """Configurable resource bounds for analysis sessions."""
    max_sample_size: int = MAX_SAMPLE_SIZE
    max_pcap_size: int = MAX_PCAP_SIZE
    max_packets: int = MAX_PACKETS
    max_tracked_connections: int = MAX_TRACKED_CONNECTIONS
    max_timestamps_per_connection: int = MAX_TIMESTAMPS_PER_CONNECTION
    max_strings: int = MAX_STRINGS
    max_string_length: int = MAX_STRING_LENGTH
    max_log_rows: int = MAX_LOG_ROWS
    max_regshot_size: int = MAX_REGSHOT_SIZE
    max_regshot_lines: int = MAX_REGSHOT_LINES
    max_report_size: int = MAX_REPORT_SIZE
    analysis_timeout: int = ANALYSIS_TIMEOUT
    adapter_timeout: int = ADAPTER_TIMEOUT
    max_stdout_bytes: int = MAX_STDOUT_BYTES
    max_stderr_bytes: int = MAX_STDERR_BYTES


    def check_file_size(self, file_path: Path, max_bytes: int, file_label: str = "File") -> Tuple[bool, Optional[str]]:
        """Checks if file size is within policy. Returns (is_ok, error_or_warning_message)."""
        p = Path(file_path)
        if not p.exists():
            return False, f"{file_label} does not exist: {file_path}"
        
        size = p.stat().st_size
        if size > max_bytes:
            return False, f"{file_label} size ({size:,} bytes) exceeds resource limit ({max_bytes:,} bytes)."
        return True, None

    def check_sample(self, file_path: Path) -> Tuple[bool, Optional[str]]:
        return self.check_file_size(file_path, self.max_sample_size, "Sample binary")

    def check_pcap(self, file_path: Path) -> Tuple[bool, Optional[str]]:
        return self.check_file_size(file_path, self.max_pcap_size, "PCAP trace")

    def check_procmon(self, file_path: Path) -> Tuple[bool, Optional[str]]:
        # Procmon CSV file size check (allow up to 200MB file, max_log_rows controls parsed rows)
        return self.check_file_size(file_path, 200 * 1024 * 1024, "Procmon CSV")

    def check_regshot(self, file_path: Path) -> Tuple[bool, Optional[str]]:
        return self.check_file_size(file_path, self.max_regshot_size, "Regshot diff log")
