"""
0206 - Privacy & Data Loss Prevention (DLP) Module
Sanitizes sensitive personal identifiers, usernames, local filesystem paths,
machine hostnames, and credentials before presentation or LLM transmission.
Guarantees non-mutating transformations (returns new objects).
"""
import re
import copy
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Set


class PrivacyMode(str, Enum):
    STRICT = "strict"
    STANDARD = "standard"
    NONE = "none"


class PrivacyRedactor:
    """
    Sanitizes telemetry data according to the configured privacy policy.
    Guaranteed to be pure/idempotent: does NOT mutate the input object.
    """

    def __init__(self, mode: Union[PrivacyMode, str] = PrivacyMode.STRICT):
        if isinstance(mode, str):
            mode = PrivacyMode(mode.lower())
        self.mode = mode
        self.known_usernames: Set[str] = set()

        # Regex patterns for sensitive data
        # 1. Windows user path: C:\Users\<username>\...
        self._win_user_re = re.compile(r'([a-zA-Z]:\\Users\\)([^\\]+)(\\.*)?', re.IGNORECASE)
        # 2. Linux/Unix user path: /(home|Users)/<username>/...
        self._linux_user_re = re.compile(r'(/(?:home|Users)/)([^/]+)(/.*)?')
        # 3. Hostnames in analysis stations
        self._host_re = re.compile(r'\b(DESKTOP-[A-Z0-9]+|WIN-[A-Z0-9]+|[A-Z0-9_-]+-STATION-\d+)\b', re.IGNORECASE)
        # 4. API keys and bearer tokens (including OpenAI sk- and sk-proj- keys)
        self._secret_re = re.compile(r'(sk-[a-zA-Z0-9_\-]{20,}|Bearer\s+[a-zA-Z0-9_\-\.]{20,}|(?:api[_-]?key|password|secret)[\s:=]+[\'\"][^\'\"]+[\'\"])', re.IGNORECASE)
        # 5. Private keys (PEM format)
        self._privkey_re = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----')

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
        """Sanitizes a single string according to active privacy policy."""
        if not text or self.mode == PrivacyMode.NONE:
            return text

        # Redact secrets and private keys regardless of mode (strict & standard)
        text = self._secret_re.sub(r'[REDACTED_SECRET]', text)
        text = self._privkey_re.sub(r'[REDACTED_PRIVATE_KEY]', text)

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
            text = re.sub(rf'\b{re.escape(u)}\b', '<REDACTED_USER>', text, flags=re.IGNORECASE)

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

    def audit_for_transmission(self, data: Any) -> tuple[bool, List[str]]:
        """
        Performs a mandatory DLP audit on data scheduled for external/remote transmission.
        Returns (is_safe, violation_reasons).
        If unsafe data remains, remote transmission MUST be blocked.
        """
        violations: List[str] = []

        def _check_string(val: str, path_prefix: str = ""):
            if self._secret_re.search(val):
                violations.append(f"Unredacted credential or API key found at {path_prefix}")
            if self._privkey_re.search(val):
                violations.append(f"Unredacted private key found at {path_prefix}")
            if self.mode == PrivacyMode.STRICT:
                if self._win_user_re.search(val) and "<REDACTED_USER>" not in val:
                    violations.append(f"Unredacted Windows user path found at {path_prefix}")
                if self._linux_user_re.search(val) and "<REDACTED_USER>" not in val:
                    violations.append(f"Unredacted Linux user path found at {path_prefix}")
                if self._host_re.search(val) and "<REDACTED_HOST>" not in val:
                    violations.append(f"Unredacted station hostname found at {path_prefix}")

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
        return is_safe, violations


BLOCK_REMOTE_TRANSMISSION = "BLOCK_REMOTE_TRANSMISSION"


class DLPViolationError(RuntimeError):
    """Raised when sensitive unredacted telemetry violates the DLP boundary."""
    pass

