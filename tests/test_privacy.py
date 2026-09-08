"""
Unit Tests for 0206 Privacy & DLP Module
"""
import unittest
from core.privacy import PrivacyRedactor, PrivacyMode


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

    def test_hostname_redaction(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        text = "Executed on DESKTOP-XY9876 in sandbox."
        redacted = redactor.redact(text)
        self.assertNotIn("DESKTOP-XY9876", redacted)
        self.assertIn("<REDACTED_HOST>", redacted)

    def test_secret_redaction(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STANDARD)
        text = "Authorization token: sk-abcdef12345678901234567890abcdef"
        redacted = redactor.redact(text)
        self.assertNotIn("sk-abcdef", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_input_non_mutation(self):
        redactor = PrivacyRedactor(mode=PrivacyMode.STRICT)
        original_dict = {
            "path": r"C:\Users\Alice\test.exe",
            "nested": {
                "user": "Alice",
                "logs": ["User Alice logged in from /home/alice/box"]
            }
        }
        # Run redaction
        clean_dict = redactor.redact(original_dict)

        # Assert original is unchanged
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


if __name__ == "__main__":
    unittest.main()
