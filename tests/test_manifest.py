"""
Unit Tests for 0206 Analysis Manifest & Reproducibility Module
"""
import unittest
import tempfile
import json
from pathlib import Path
from core.manifest import AnalysisManifest, hash_file_streaming


class TestAnalysisManifest(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = Path(self.temp_dir.name) / "test_file.bin"
        self.test_file.write_bytes(b"HELLO 0206 FORENSIC PLATFORM" * 100)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_streaming_hash(self):
        hashes = hash_file_streaming(self.test_file)
        self.assertIn("sha256", hashes)
        self.assertIn("md5", hashes)
        self.assertIn("sha1", hashes)
        self.assertEqual(len(hashes["sha256"]), 64)
        self.assertEqual(len(hashes["md5"]), 32)

    def test_manifest_creation_and_export(self):
        manifest = AnalysisManifest()
        manifest.record_artifact("sample", self.test_file)
        manifest.sample_filename = self.test_file.name
        manifest.analyzers_enabled.append("PEStaticAnalyzer")
        manifest.complete()

        export_path = Path(self.temp_dir.name) / "manifest.json"
        manifest.export_json(export_path)
        self.assertTrue(export_path.exists())

        loaded = json.loads(export_path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["engine_name"], "0206")
        self.assertEqual(loaded["sample_filename"], "test_file.bin")
        self.assertIn("sample", loaded["artifacts"])
        self.assertIsNotNone(loaded["end_time_utc"])


if __name__ == "__main__":
    unittest.main()
