"""
0206 - External Process Security Guard
Enforces secure process execution:
- Strict argument array passing (shell=False mandatory)
- Timeout bounds (prevent runaway analysis processes)
- Output size limits with temporary-file backing (prevent memory exhaustion)
- Environment sanitization (prevents leakage of API keys or secrets to sub-processes)
- Output hashing (SHA256 of stdout/stderr for auditability)
- Truncation tracking
"""
import os
import time
import hashlib
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

from config import MAX_STDOUT_BYTES, MAX_STDERR_BYTES


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
    truncated: bool = False


# Safe environment variables to propagate to external tools (excluding sensitive analyst identity)
SAFE_ENV_VARS = {
    "PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR",
    "LANG", "LC_ALL", "SHELL", "TERM"
}

BLOCKED_ENV_SUBSTRINGS = (
    "key", "secret", "token", "password", "auth", "credential", "private", "api"
)


def sanitize_environment(
    extra_env: Optional[Dict[str, str]] = None,
    isolate_home: bool = True
) -> Dict[str, str]:
    """
    Constructs a sterile environment dictionary, stripping API keys, secrets,
    and avoiding propagation of real analyst HOME and USER.
    """
    clean_env: Dict[str, str] = {}
    for k in SAFE_ENV_VARS:
        if k in os.environ:
            clean_env[k] = os.environ[k]

    # Provide a controlled temporary directory for HOME and generic USER
    if isolate_home:
        controlled_home = os.environ.get("TMPDIR") or os.environ.get("TEMP") or tempfile.gettempdir()
        clean_env["HOME"] = controlled_home
        clean_env["USER"] = "analyst"
        clean_env["LOGNAME"] = "analyst"

    if extra_env:
        for k, v in extra_env.items():
            k_lower = k.lower()
            if not any(secret_term in k_lower for secret_term in BLOCKED_ENV_SUBSTRINGS):
                clean_env[k] = v
    return clean_env


import signal

try:
    import resource
    HAS_RESOURCE_MODULE = True
except ImportError:
    HAS_RESOURCE_MODULE = False


def _make_posix_preexec(timeout_sec: int, max_out_bytes: int):
    """Configures safe POSIX resource limits on child process where supported."""
    def _preexec():
        if HAS_RESOURCE_MODULE:
            try:
                cpu_bound = max(1, int(timeout_sec)) + 5
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_bound, cpu_bound + 2))
            except (ValueError, OSError, AttributeError):
                pass
            try:
                fsize_bound = max(max_out_bytes * 2, 50 * 1024 * 1024)
                resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_bound, fsize_bound))
            except (ValueError, OSError, AttributeError):
                pass
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 2048))
            except (ValueError, OSError, AttributeError):
                pass
    return _preexec


def safe_run_process(
    cmd_args: List[str],
    timeout: int = 60,
    cwd: Optional[Path] = None,
    extra_env: Optional[Dict[str, str]] = None,
    max_output_bytes: Optional[int] = None,
    max_stdout_bytes: Optional[int] = None,
    max_stderr_bytes: Optional[int] = None
) -> ProcessExecutionResult:
    """
    Executes an external binary securely with timeout, process-tree cleanup, and bounded I/O.
    Guarantees:
    - Never executes via shell interpreter.
    - Validates timeout and output bounds (rejects negative/pathological values).
    - Terminates entire process group on timeout (POSIX start_new_session=True).
    - Enforces safe POSIX resource limits where supported.
    - Zero unbounded memory buffering: stdout/stderr spool directly to OS temporary files.
    - Caps output at max_stdout_bytes and max_stderr_bytes with truncation tracking.
    """
    if not cmd_args or not isinstance(cmd_args, (list, tuple)):
        raise ValueError("cmd_args must be a non-empty list of string arguments.")

    # Validate timeout
    if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 86400:
        raise ValueError(f"Invalid timeout: {timeout}. Must be a positive number up to 86400 seconds.")

    # Validate limit parameters
    if max_stdout_bytes is not None and max_stdout_bytes <= 0:
        raise ValueError(f"Invalid max_stdout_bytes: {max_stdout_bytes}. Must be a positive integer.")
    if max_stderr_bytes is not None and max_stderr_bytes <= 0:
        raise ValueError(f"Invalid max_stderr_bytes: {max_stderr_bytes}. Must be a positive integer.")
    if max_output_bytes is not None and max_output_bytes <= 0:
        raise ValueError(f"Invalid max_output_bytes: {max_output_bytes}. Must be a positive integer.")

    # Resolve limits
    limit_stdout = max_stdout_bytes if max_stdout_bytes is not None else (max_output_bytes if max_output_bytes is not None else MAX_STDOUT_BYTES)
    limit_stderr = max_stderr_bytes if max_stderr_bytes is not None else ((max_output_bytes // 2) if max_output_bytes is not None else MAX_STDERR_BYTES)

    # Convert all arguments to strings
    safe_args = [str(arg) for arg in cmd_args]
    clean_env = sanitize_environment(extra_env)

    work_dir = cwd if (cwd and Path(cwd).exists()) else None
    start_time = time.perf_counter()
    timed_out = False
    truncated = False

    try:
        # Use OS file-backed temporary storage to avoid buffering huge output into RAM
        with tempfile.TemporaryFile(mode="w+b") as out_f, tempfile.TemporaryFile(mode="w+b") as err_f:
            popen_kwargs: Dict[str, Any] = {
                "cwd": str(work_dir) if work_dir else None,
                "env": clean_env,
                "stdout": out_f,
                "stderr": err_f,
                "shell": False  # MANDATORY SECURITY REQUIREMENT
            }

            # POSIX process isolation and process-tree grouping
            if os.name != "nt":
                popen_kwargs["start_new_session"] = True
                if HAS_RESOURCE_MODULE:
                    popen_kwargs["preexec_fn"] = _make_posix_preexec(int(timeout), limit_stdout + limit_stderr)

            proc = subprocess.Popen(safe_args, **popen_kwargs)

            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                # Terminate entire process group to avoid leaving orphan descendants
                if os.name != "nt" and hasattr(os, "killpg") and hasattr(proc, "pid"):
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except Exception:
                        proc.kill()
                else:
                    proc.kill()
                proc.wait()

            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

            # Read stdout up to limit + 1 to detect truncation without loading entire file
            out_f.seek(0)
            raw_out = out_f.read(limit_stdout + 1)
            if len(raw_out) > limit_stdout:
                truncated = True
                raw_out = raw_out[:limit_stdout]

            err_f.seek(0)
            raw_err = err_f.read(limit_stderr + 1)
            if len(raw_err) > limit_stderr:
                truncated = True
                raw_err = raw_err[:limit_stderr]

            stdout_text = raw_out.decode("utf-8", errors="ignore")
            stderr_text = raw_err.decode("utf-8", errors="ignore")

            return ProcessExecutionResult(
                command=safe_args,
                exit_code=proc.returncode if not timed_out else None,
                duration_ms=duration_ms,
                stdout=stdout_text,
                stderr=stderr_text,
                stdout_hash=hashlib.sha256(raw_out).hexdigest(),
                stderr_hash=hashlib.sha256(raw_err).hexdigest(),
                timed_out=timed_out,
                error_message=f"Process timed out after {timeout} seconds." if timed_out else None,
                truncated=truncated
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
            error_message=str(ex),
            truncated=False
        )



class SafeProcessGuard:
    """Wrapper class providing static run method for safe process execution."""

    @staticmethod
    def run(
        cmd_args: List[str],
        timeout_sec: int = 60,
        cwd: Optional[Path] = None,
        extra_env: Optional[Dict[str, str]] = None,
        max_output_bytes: Optional[int] = None,
        max_stdout_bytes: Optional[int] = None,
        max_stderr_bytes: Optional[int] = None,
        timeout: Optional[int] = None
    ) -> ProcessExecutionResult:
        actual_timeout = timeout if timeout is not None else timeout_sec
        return safe_run_process(
            cmd_args=cmd_args,
            timeout=actual_timeout,
            cwd=cwd,
            extra_env=extra_env,
            max_output_bytes=max_output_bytes,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes
        )
