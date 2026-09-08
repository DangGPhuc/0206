"""
0206 - Resource Policy Unit Tests
Phase 34: test_resource_policy.py
"""
import unittest
import tempfile
import os
from pathlib import Path
from core.resource_policy import ResourcePolicy


class TestResourcePolicy(unittest.TestCase):

    def test_sample_size_within_policy(self):
        policy = ResourcePolicy(max_sample_size=1024 * 1024)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"M" * 512)
            temp_path = Path(f.name)
        try:
            ok, err = policy.check_sample(temp_path)
            self.assertTrue(ok)
            self.assertIsNone(err)
        finally:
            if temp_path.exists():
                os.remove(temp_path)

    def test_sample_size_exceeded(self):
        policy = ResourcePolicy(max_sample_size=100)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"M" * 200)
            temp_path = Path(f.name)
        try:
            ok, err = policy.check_sample(temp_path)
            self.assertFalse(ok)
            self.assertIn("exceeds resource limit", err)
        finally:
            if temp_path.exists():
                os.remove(temp_path)

    def test_non_existent_file(self):
        policy = ResourcePolicy()
        fake_path = Path("/tmp/definitely_not_existing_0206_sample.exe")
        ok, err = policy.check_sample(fake_path)
        self.assertFalse(ok)
        self.assertIn("does not exist", err)


if __name__ == "__main__":
    unittest.main()
