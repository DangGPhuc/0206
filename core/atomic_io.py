"""
0206 - Atomic I/O & Safe Permissions Utility
Provides atomic file write primitives and cross-platform safe permission handling:
- Writes to a unique temporary file on the same filesystem.
- Flushes and fsyncs to ensure data persistence.
- Applies restricted POSIX permissions (0700 for directories, 0600 for sensitive files).
- Atomically replaces the target path via os.replace to prevent truncated or corrupted case files.
"""
import os
import json
import tempfile
from pathlib import Path
from typing import Any, Union, Optional


def set_posix_permissions(path: Union[str, Path], mode: int) -> None:
    """Sets file or directory permissions safely on POSIX platforms without breaking Windows."""
    if os.name != "nt":
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def atomic_write_text(
    dest_path: Union[str, Path],
    content: str,
    encoding: str = "utf-8",
    mode: int = 0o600
) -> Path:
    """
    Atomically writes string content to dest_path via a same-directory temporary file.
    Ensures that partially written files are never exposed to readers on crash.
    """
    dest = Path(dest_path).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    set_posix_permissions(dest.parent, 0o700)

    # Use same directory to guarantee atomic rename across filesystems
    fd, tmp_path_str = tempfile.mkstemp(dir=dest.parent, prefix=f".tmp_{dest.name}_")
    tmp_path = Path(tmp_path_str)

    try:
        with open(fd, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())

        set_posix_permissions(tmp_path, mode)
        os.replace(tmp_path, dest)
        return dest
    except Exception:
        if tmp_path.exists():
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def atomic_write_json(
    dest_path: Union[str, Path],
    data: Any,
    indent: int = 2,
    mode: int = 0o600,
    default: Optional[Any] = None
) -> Path:
    """Atomically writes JSON-serializable data to dest_path."""
    content = json.dumps(data, indent=indent, default=default or str)
    return atomic_write_text(dest_path, content, mode=mode)
