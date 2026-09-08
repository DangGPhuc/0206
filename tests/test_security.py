"""
Unit Tests for 0206 Security, Hygiene, and Resource Limits
"""
import unittest
import tempfile
from pathlib import Path
from core.validators import validate_file_size
from scripts.precommit_data_guard import BLOCKED_EXTENSIONS, SECRET_PATTERNS


class TestSecurityControls(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_resource_size_limits(self):
        big_file = Path(self.temp_dir.name) / "huge.bin"
        big_file.write_bytes(b"A" * 1024)

        # Allow 2048 bytes -> OK
        valid, msg = validate_file_size(big_file, max_bytes=2048)
        self.assertTrue(valid)

        # Allow 512 bytes -> Exceeds limit
        valid, msg = validate_file_size(big_file, max_bytes=512)
        self.assertFalse(valid)
        self.assertIn("exceeds safety limit", msg)

    def test_precommit_blocked_extensions(self):
        for ext in [".exe", ".dll", ".pcap", ".dmp", ".key", ".pem"]:
            self.assertIn(ext, BLOCKED_EXTENSIONS)

    def test_secret_pattern_detection(self):
        sample_secret = "Authorization: Bearer sk-1234567890abcdef1234567890"
        matched = False
        for pattern, desc in SECRET_PATTERNS:
            if pattern.search(sample_secret):
                matched = True
                break
        self.assertTrue(matched)


if __name__ == "__main__":
    unittest.main()
