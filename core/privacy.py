"""
0206 - Privacy & Data Loss Prevention (DLP) Module
Provides best-effort privacy and secret redaction for sensitive personal identifiers,
usernames, local filesystem paths, machine hostnames, API tokens, and credentials
before presentation or remote transmission.
Guarantees non-mutating transformations (pure functions returning new objects).
"""
import re
import copy
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Set, Tuple


class PrivacyMode(str, Enum):
    STRICT = "strict"
    STANDARD = "standard"
    NONE = "none"


class DLPStatus(str, Enum):
    SAFE = "SAFE"
    REDACTED = "REDACTED"
    BLOCKED = "BLOCKED"


class DLPAuditResult(tuple):
    """
    Tuple-compatible audit result: (is_safe, violations).
    Provides structured DLP status (SAFE, REDACTED, BLOCKED), is_safe flag, and violations list.
    """
    def __new__(cls, is_safe: bool, violations: List[str], status: DLPStatus):
        return super().__new__(cls, (is_safe, violations))

    @property
    def is_safe(self) -> bool:
        return self[0]

    @property
    def violations(self) -> List[str]:
        return self[1]

    @property
    def status(self) -> DLPStatus:
        return self._status

    def __init__(self, is_safe: bool, violations: List[str], status: DLPStatus):
        self._status = status


class PrivacyRedactor:
    """
    Provides best-effort privacy and secret redaction according to configured privacy policy.
    Guaranteed to be pure/idempotent: does NOT mutate the input object.
    """

    def __init__(self, mode: Union[PrivacyMode, str] = PrivacyMode.STRICT):
        if isinstance(mode, str):
            mode = PrivacyMode(mode.lower())
        self.mode = mode
        self.known_usernames: Set[str] = set()
        self.known_hostnames: Set[str] = set()

        try:
            import getpass
            current_user = getpass.getuser()
            if current_user and current_user.lower() not in ("root", "bin", "daemon", "public", "default"):
                self.known_usernames.add(current_user)
        except Exception:
            pass

        try:
            import socket
            current_host = socket.gethostname()
            if current_host and current_host.lower() not in ("localhost", "127.0.0.1"):
                self.known_hostnames.add(current_host)
        except Exception:
            pass

        # Regex patterns for sensitive paths and hostnames
        # 1. Windows user path: C:\Users\<username>\... or C:\Documents and Settings\<username>\...
        self._win_user_re = re.compile(r'([a-zA-Z]:\\(?:Users|Documents and Settings)\\)([^\\]+)(\\.*)?', re.IGNORECASE)
        # 2. Linux/Unix user path: /(home|Users|run/media|media|mnt)/<username>/...
        self._linux_user_re = re.compile(r'(/(?:home|Users|run/media|media|mnt)/)([^/]+)(/.*)?')
        # 3. Hostnames in analysis stations
        self._host_re = re.compile(r'\b(DESKTOP-[A-Z0-9]+|WIN-[A-Z0-9]+|[A-Z0-9_-]+-STATION-\d+)\b', re.IGNORECASE)

        # High-Risk Secret & Credential Detectors (Phase 5)
        # 4. AWS Access Key ID (e.g. AKIA...)
        self._aws_key_re = re.compile(r'\b(AKIA[0-9A-Z]{16})\b')
        # 5. GitHub Personal Access Tokens (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)
        self._github_token_re = re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b')
        # 6. JSON Web Tokens (JWT: eyJ...)
        self._jwt_re = re.compile(r'\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-]+)\b')
        # 7. Bearer Tokens and Authorization headers
        self._bearer_re = re.compile(r'(?:Bearer\s+|Authorization:\s*(?:Bearer\s+|Basic\s+))([a-zA-Z0-9_\-\.=]{20,})', re.IGNORECASE)
        # 8. Private Key blocks (PEM, RSA, OpenSSH, EC, DSA)
        self._privkey_re = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----')
        # 9. Database Connection Strings
        self._conn_str_re = re.compile(r'\b((?:postgres|postgresql|mysql|mongodb|redis|amqp|mssql)://[^\s\'"]+)', re.IGNORECASE)
        # 10. Passwords in common configuration / assignment formats
        self._config_pwd_re = re.compile(r'((?:password|passwd|pwd|db_pass|secret_key)[\s:=]+[\'"])([^\'"]{3,})([\'"])', re.IGNORECASE)
        # 11. Generic API Keys (OpenAI sk-, Anthropic sk-ant-, generic api_key)
        self._api_key_re = re.compile(r'\b(sk-[a-zA-Z0-9_\-]{20,}|sk-ant-[a-zA-Z0-9_\-]{20,}|(?:api[_-]?key|access[_-]?token)[\s:=]+[\'"][a-zA-Z0-9_\-]{16,}[\'"])\b', re.IGNORECASE)
        # 12. Combined secret pattern for quick scanning
        self._secret_re = re.compile(r'(sk-[a-zA-Z0-9_\-]{20,}|sk-ant-[a-zA-Z0-9_\-]{20,}|Bearer\s+[a-zA-Z0-9_\-\.]{20,}|(?:api[_-]?key|password|secret)[\s:=]+[\'\"][^\'\"]+[\'\"])', re.IGNORECASE)

    def _harvest_usernames(self, data: Any):
        """Scans input structure to register any username patterns for full text scrubbing."""
        if isinstance(data, str):
            for m in self._win_user_re.finditer(data):
                u = m.group(2)
                if u and u.lower() not in ("public", "default", "all users"):
                    self.known_usernames.add(u)
            for m in self._linux_user_re.finditer(data):
                u = m.group(2)
                if u and u.lower() not in ("root", "bin", "daemon"):
                    self.known_usernames.add(u)
        elif isinstance(data, dict):
            for k, v in data.items():
                if isinstance(k, str):
                    self._harvest_usernames(k)
                self._harvest_usernames(v)
        elif isinstance(data, (list, tuple, set)):
            for item in data:
                self._harvest_usernames(item)

    def redact_string(self, text: str) -> str:
        """Sanitizes a single string using best-effort redaction."""
        if not text or self.mode == PrivacyMode.NONE:
            return text

        # Redact secrets and private keys regardless of mode (strict & standard)
        text = self._privkey_re.sub(r'[REDACTED_PRIVATE_KEY]', text)
        text = self._aws_key_re.sub(r'[REDACTED_AWS_KEY]', text)
        text = self._github_token_re.sub(r'[REDACTED_GITHUB_TOKEN]', text)
        text = self._jwt_re.sub(r'[REDACTED_JWT]', text)
        text = self._conn_str_re.sub(r'[REDACTED_CONNECTION_STRING]', text)
        text = self._config_pwd_re.sub(r'\1<REDACTED_PASSWORD>\3', text)
        text = self._secret_re.sub(r'[REDACTED_SECRET]', text)
        text = self._bearer_re.sub(r'Bearer [REDACTED_BEARER_TOKEN]', text)
        text = self._api_key_re.sub(r'[REDACTED_API_KEY]', text)

        # Harvest user identity if present in paths
        for m in self._win_user_re.finditer(text):
            u = m.group(2)
            if u and u.lower() not in ("public", "default", "all users"):
                self.known_usernames.add(u)
        for m in self._linux_user_re.finditer(text):
            u = m.group(2)
            if u and u.lower() not in ("root", "bin", "daemon"):
                self.known_usernames.add(u)

        # Redact user paths
        text = self._win_user_re.sub(r'\1<REDACTED_USER>\3', text)
        text = self._linux_user_re.sub(r'\1<REDACTED_USER>\3', text)

        # Redact known usernames in standalone text
        for u in self.known_usernames:
            if len(u) >= 3:
                text = re.sub(rf'\b{re.escape(u)}\b', '<REDACTED_USER>', text, flags=re.IGNORECASE)

        # Redact known hostnames in standalone text
        for h in self.known_hostnames:
            if len(h) >= 3:
                text = re.sub(rf'\b{re.escape(h)}\b', '<REDACTED_HOST>', text, flags=re.IGNORECASE)

        if self.mode == PrivacyMode.STRICT:
            text = self._host_re.sub(r'<REDACTED_HOST>', text)

        return text

    def redact(self, data: Any) -> Any:
        """
        Recursively redacts strings, dictionaries, lists, and primitives.
        Guarantees that input `data` is NOT mutated.
        """
        if self.mode == PrivacyMode.NONE:
            return copy.deepcopy(data)

        # First harvest any usernames embedded in paths
        self._harvest_usernames(data)

        return self._redact_recursive(data)

    def _redact_recursive(self, data: Any) -> Any:
        if isinstance(data, str):
            return self.redact_string(data)
        elif isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                new_key = self.redact_string(k) if isinstance(k, str) else k
                new_dict[new_key] = self._redact_recursive(v)
            return new_dict
        elif isinstance(data, (list, tuple, set)):
            new_list = [self._redact_recursive(item) for item in data]
            if isinstance(data, tuple):
                return tuple(new_list)
            elif isinstance(data, set):
                return set(new_list)
            return new_list
        elif hasattr(data, "model_dump"):
            return self._redact_recursive(data.model_dump())
        elif hasattr(data, "dict"):
            return self._redact_recursive(data.dict())
        else:
            return copy.deepcopy(data)

    def audit_for_transmission(self, data: Any) -> DLPAuditResult:
        """
        Performs a mandatory DLP audit on data scheduled for external/remote transmission.
        Returns DLPAuditResult(is_safe, violations, status) where status is:
          - SAFE: No credentials, tokens, or private paths detected.
          - REDACTED: Content contained sensitive markers that were safely sanitized.
          - BLOCKED: Unredacted credentials, keys, or paths remain; transmission must be blocked.
        """
        violations: List[str] = []
        has_redacted_markers = False

        def _check_string(val: str, path_prefix: str = ""):
            nonlocal has_redacted_markers
            if "[REDACTED_" in val or "<REDACTED_" in val:
                has_redacted_markers = True

            # Unredacted secrets check
            if self._privkey_re.search(val) and "[REDACTED_PRIVATE_KEY]" not in val:
                violations.append(f"Unredacted private key found at {path_prefix}")
            if self._aws_key_re.search(val) and "[REDACTED_AWS_KEY]" not in val:
                violations.append(f"Unredacted AWS Access Key found at {path_prefix}")
            if self._github_token_re.search(val) and "[REDACTED_GITHUB_TOKEN]" not in val:
                violations.append(f"Unredacted GitHub Token found at {path_prefix}")
            if self._jwt_re.search(val) and "[REDACTED_JWT]" not in val:
                violations.append(f"Unredacted JWT found at {path_prefix}")
            if self._conn_str_re.search(val) and "[REDACTED_CONNECTION_STRING]" not in val:
                violations.append(f"Unredacted database connection string found at {path_prefix}")
            if self._api_key_re.search(val) and "[REDACTED_API_KEY]" not in val and "[REDACTED_SECRET]" not in val:
                violations.append(f"Unredacted API key found at {path_prefix}")
            if self._secret_re.search(val) and "[REDACTED_SECRET]" not in val and "[REDACTED_API_KEY]" not in val:
                violations.append(f"Unredacted secret or token found at {path_prefix}")

            if self.mode == PrivacyMode.STRICT:
                if self._win_user_re.search(val) and "<REDACTED_USER>" not in val:
                    violations.append(f"Unredacted Windows user path found at {path_prefix}")
                if self._linux_user_re.search(val) and "<REDACTED_USER>" not in val:
                    violations.append(f"Unredacted Linux user path found at {path_prefix}")
                if self._host_re.search(val) and "<REDACTED_HOST>" not in val:
                    violations.append(f"Unredacted station hostname found at {path_prefix}")
                for u in self.known_usernames:
                    if len(u) >= 3 and re.search(rf'\b{re.escape(u)}\b', val, re.IGNORECASE) and "<REDACTED_USER>" not in val:
                        violations.append(f"Unredacted username '{u}' found at {path_prefix}")
                for h in self.known_hostnames:
                    if len(h) >= 3 and re.search(rf'\b{re.escape(h)}\b', val, re.IGNORECASE) and "<REDACTED_HOST>" not in val:
                        violations.append(f"Unredacted hostname '{h}' found at {path_prefix}")

        def _scan(obj: Any, prefix: str = ""):
            if isinstance(obj, str):
                _check_string(obj, prefix)
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    _check_string(str(k), f"{prefix}.{k}")
                    _scan(v, f"{prefix}.{k}")
            elif isinstance(obj, (list, tuple, set)):
                for idx, item in enumerate(obj):
                    _scan(item, f"{prefix}[{idx}]")

        _scan(data, "payload")
        is_safe = len(violations) == 0

        if not is_safe:
            status = DLPStatus.BLOCKED
        elif has_redacted_markers:
            status = DLPStatus.REDACTED
        else:
            status = DLPStatus.SAFE

        return DLPAuditResult(is_safe, violations, status)

    # Alias for naming consistency
    audit_for_remote_transmission = audit_for_transmission


BLOCK_REMOTE_TRANSMISSION = "BLOCK_REMOTE_TRANSMISSION"


class DLPViolationError(RuntimeError):
    """Raised when sensitive unredacted telemetry violates the DLP boundary."""
    pass
