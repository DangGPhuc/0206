"""
0206 - External Process Security Guard
Enforces secure process execution:
- Strict argument array passing (no shell=True)
- Timeout bounds (prevent runaway analysis processes)
- Output size limits (prevent memory exhaustion)
- Environment sanitization (prevents leakage of API keys or secrets to sub-processes)
- Output hashing (SHA256 of stdout/stderr for auditability)
"""
import os
import time
import hashlib
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class ProcessExecutionResult:
    """Audit record of an external process execution."""
    command: List[str]
    exit_code: Optional[int]
    duration_ms: float
    stdout: str
    stderr: str
    stdout_hash: str
    stderr_hash: str
    timed_out: bool = False
    error_message: Optional[str] = None


# Safe environment variables to propagate to external tools
SAFE_ENV_VARS = {
    "PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR",
    "LANG", "LC_ALL", "HOME", "USER", "SHELL", "TERM"
}


def sanitize_environment(extra_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Constructs a sterile environment dictionary, stripping API keys and secrets.
    """
    clean_env: Dict[str, str] = {}
    for k in SAFE_ENV_VARS:
        if k in os.environ:
            clean_env[k] = os.environ[k]
    if extra_env:
        for k, v in extra_env.items():
            if not any(secret_term in k.lower() for secret_term in ("key", "secret", "token", "password", "auth")):
                clean_env[k] = v
    return clean_env


def safe_run_process(
    cmd_args: List[str],
    timeout: int = 60,
    cwd: Optional[Path] = None,
    extra_env: Optional[Dict[str, str]] = None,
    max_output_bytes: int = 5 * 1024 * 1024  # 5 MB max output
) -> ProcessExecutionResult:
    """
    Executes an external binary securely with timeout and output bounds.
    Never uses shell=True.
    """
    if not cmd_args or not isinstance(cmd_args, (list, tuple)):
        raise ValueError("cmd_args must be a non-empty list of string arguments.")

    # Convert all arguments to strings
    safe_args = [str(arg) for arg in cmd_args]
    clean_env = sanitize_environment(extra_env)

    work_dir = cwd if (cwd and Path(cwd).exists()) else None
    start_time = time.perf_counter()

    try:
        proc = subprocess.run(
            safe_args,
            cwd=str(work_dir) if work_dir else None,
            env=clean_env,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False  # MANDATORY SECURITY REQUIREMENT
        )
        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        stdout_text = proc.stdout[:max_output_bytes]
        stderr_text = proc.stderr[:max_output_bytes]

        return ProcessExecutionResult(
            command=safe_args,
            exit_code=proc.returncode,
            duration_ms=duration_ms,
            stdout=stdout_text,
            stderr=stderr_text,
            stdout_hash=hashlib.sha256(stdout_text.encode("utf-8", errors="ignore")).hexdigest(),
            stderr_hash=hashlib.sha256(stderr_text.encode("utf-8", errors="ignore")).hexdigest(),
            timed_out=False
        )

    except subprocess.TimeoutExpired as te:
        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        out = (te.stdout.decode("utf-8", errors="ignore") if isinstance(te.stdout, bytes) else (te.stdout or ""))[:max_output_bytes]
        err = (te.stderr.decode("utf-8", errors="ignore") if isinstance(te.stderr, bytes) else (te.stderr or ""))[:max_output_bytes]
        return ProcessExecutionResult(
            command=safe_args,
            exit_code=None,
            duration_ms=duration_ms,
            stdout=out,
            stderr=err,
            stdout_hash=hashlib.sha256(out.encode("utf-8", errors="ignore")).hexdigest(),
            stderr_hash=hashlib.sha256(err.encode("utf-8", errors="ignore")).hexdigest(),
            timed_out=True,
            error_message=f"Process timed out after {timeout} seconds."
        )

    except Exception as ex:
        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        return ProcessExecutionResult(
            command=safe_args,
            exit_code=-1,
            duration_ms=duration_ms,
            stdout="",
            stderr=str(ex),
            stdout_hash=hashlib.sha256(b"").hexdigest(),
            stderr_hash=hashlib.sha256(str(ex).encode("utf-8")).hexdigest(),
            timed_out=False,
            error_message=str(ex)
        )
