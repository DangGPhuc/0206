#!/usr/bin/env python3
"""
0206 - Pre-commit Data & Supply-Chain Security Guard
Inspects git staged files to prevent accidental commits of:
- Compiled binaries (.exe, .dll, .sys, .bin, .so)
- Network PCAP traces (.pcap, .pcapng)
- Memory crash dumps (.dmp, .mem)
- Staged API keys or secret tokens
- Files exceeding size thresholds (> 5MB)
"""
import sys
import subprocess
import re
from pathlib import Path

# Maximum file size allowed in repository commits (5 MB)
MAX_STAGED_FILE_SIZE = 5 * 1024 * 1024

# Disallowed file extensions
BLOCKED_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bin", ".raw", ".elf", ".so", ".dylib",
    ".pcap", ".pcapng", ".cap", ".dmp", ".mem", ".core",
    ".key", ".pem", ".pkcs12", ".pfx"
}

# Secret / API key and proprietary marker patterns
SECRET_PATTERNS = [
    (re.compile(r'sk-[a-zA-Z0-9_\-]{20,}'), "OpenAI API Key"),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "GitHub Personal Access Token"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID"),
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "Private Key Header"),
    (re.compile(r'(?:SANS\s+FOR610|Maldev\s+Academy\s+Courseware)', re.IGNORECASE), "Proprietary Copyrighted Courseware")
]


def check_staged_files() -> bool:
    """Returns True if all staged files pass hygiene checks, False if violations found."""
    try:
        cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        staged_files = [f.strip() for f in proc.stdout.splitlines() if f.strip()]
    except Exception as e:
        print(f"[!] Warning: Unable to inspect git index: {e}")
        return True

    violations = []

    for file_str in staged_files:
        p = Path(file_str)
        if not p.exists():
            continue

        ext = p.suffix.lower()
        if ext in BLOCKED_EXTENSIONS:
            violations.append(f"Blocked file extension '{ext}': {file_str}")

        # Check file size
        size = p.stat().st_size
        if size > MAX_STAGED_FILE_SIZE:
            violations.append(f"File size {size:,} bytes exceeds 5MB limit: {file_str}")

        # Check content for secrets (text files only)
        if ext in (".py", ".json", ".md", ".txt", ".yml", ".yaml", ".sh", ".env"):
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                for pattern, secret_type in SECRET_PATTERNS:
                    if pattern.search(content):
                        violations.append(f"Potential secret detected ({secret_type}) in: {file_str}")
            except Exception:
                pass

    if violations:
        print("\n" + "=" * 60)
        print("❌ PRE-COMMIT SECURITY GUARD REJECTED STAGED FILES:")
        print("=" * 60)
        for v in violations:
            print(f"  • {v}")
        print("\nAction Required:")
        print("  1. Remove sensitive files from git staging with: git reset HEAD <file>")
        print("  2. Ensure sensitive data is listed in .gitignore.")
        print("=" * 60 + "\n")
        return False

    return True


if __name__ == "__main__":
    if not check_staged_files():
        sys.exit(1)
    sys.exit(0)
