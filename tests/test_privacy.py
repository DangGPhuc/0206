"""
Unit Tests for 0206 Privacy & DLP Module (P1.10)
Provides automated verification of user path scrubbing, credential redaction,
DLP transmission boundaries, and non-mutating transformations.
"""
import tempfile
import unittest
from pathlib import Path

from core.privacy import PrivacyRedactor, PrivacyMode, DLPStatus, DLPViolationError
from core.manifest import AnalysisManifest


class TestPrivacyRedactor(unittest.TestCase):

    def test_windows_user_redaction(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        raw_path = r"C:\Users\JohnDoe\AppData\Local\Temp\dropped.exe"
        redacted = redactor.redact(raw_path)
        self.assertNotIn("JohnDoe", redacted)
        self.assertIn("<REDACTED_USER>", redacted)

    def test_linux_user_redaction(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        raw_path = "/home/developer/malware/sample.bin"
        redacted = redactor.redact(raw_path)
        self.assertNotIn("developer", redacted)
        self.assertIn("<REDACTED_USER>", redacted)

    def test_linux_media_and_mount_redaction(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        mount_paths = [
            "/run/media/analyst_bob/DiskName/target.exe",
            "/media/analyst_bob/USB/malware.bin",
            "/mnt/c/Users/analyst_bob/sample.exe"
        ]
        for p in mount_paths:
            redacted = redactor.redact(p)
            self.assertNotIn("analyst_bob", redacted)
            self.assertIn("<REDACTED_USER>", redacted)

    def test_hostname_redaction(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        text = "Executed on DESKTOP-XY9876 in sandbox."
        redacted = redactor.redact(text)
        self.assertNotIn("DESKTOP-XY9876", redacted)
        self.assertIn("<REDACTED_HOST>", redacted)

    def test_secret_redaction_openai(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STANDARD)
        text = "Authorization token: sk-abcdef12345678901234567890abcdef"
        redacted = redactor.redact(text)
        self.assertNotIn("sk-abcdef", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_high_risk_credential_redaction(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        credentials = {
            "aws": "AKIAIOSFODNN7EXAMPLE",
            "github": "ghp_123456789012345678901234567890123456",
            "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
            "db": "postgresql://admin:secret123@db.internal:5432/telemetry",
            "pwd": 'db_pass = "SuperSecretPassword123"',
            "bearer": "Authorization: Bearer 1234567890abcdef1234567890abcdef"
        }
        clean = redactor.redact(credentials)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", clean["aws"])
        self.assertNotIn("ghp_1234567890", clean["github"])
        self.assertNotIn("TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ", clean["jwt"])
        self.assertNotIn("postgresql://admin:secret123", clean["db"])
        self.assertNotIn("SuperSecretPassword123", clean["pwd"])
        self.assertNotIn("1234567890abcdef1234567890abcdef", clean["bearer"])

    def test_input_non_mutation(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        original_dict = {
            "path": r"C:\Users\Alice\test.exe",
            "nested": {
                "user": "Alice",
                "logs": ["User Alice logged in from /home/alice/box"]
            }
        }
        clean_dict = redactor.redact(original_dict)

        # Assert original is untouched
        self.assertIn("Alice", original_dict["path"])
        self.assertIn("Alice", original_dict["nested"]["logs"][0])

        # Assert clean copy has no 'Alice'
        self.assertNotIn("Alice", clean_dict["path"])
        self.assertNotIn("Alice", clean_dict["nested"]["logs"][0])

    def test_none_mode(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.NONE)
        raw_path = r"C:\Users\SecretUser\payload.exe"
        redacted = redactor.redact(raw_path)
        self.assertEqual(raw_path, redacted)

    def test_dlp_transmission_audit_blocks_unredacted_secrets(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        unredacted_payload = {
            "path": "/home/victim_analyst/sample.exe",
            "key": "AKIAIOSFODNN7EXAMPLE",
            "token": "sk-proj-12345678901234567890abcdef"
        }
        audit = redactor.audit_for_transmission(unredacted_payload)
        self.assertFalse(audit.is_safe)
        self.assertEqual(audit.status, DLPStatus.BLOCKED)
        self.assertGreater(len(audit.violations), 0)

    def test_dlp_transmission_audit_accepts_redacted_payload(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        dirty_payload = {
            "path": "/home/victim_analyst/sample.exe",
            "token": "sk-proj-12345678901234567890abcdef"
        }
        clean_payload = redactor.redact(dirty_payload)
        audit = redactor.audit_for_transmission(clean_payload)
        self.assertTrue(audit.is_safe)
        self.assertEqual(audit.status, DLPStatus.REDACTED)

    def test_manifest_export_sanitizes_strict_mode(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest = AnalysisManifest(
                privacy_mode="strict",
                cli_arguments={"sample": "/home/john_doe/malware/test.exe"}
            )
            out_file = Path(tmp_dir) / "analysis_manifest.json"
            sha_file = manifest.export_json(out_file)

            self.assertTrue(out_file.exists())
            self.assertTrue(sha_file.exists())
            raw_text = out_file.read_text(encoding="utf-8")
            self.assertNotIn("john_doe", raw_text)


if __name__ == "__main__":
    unittest.main()
