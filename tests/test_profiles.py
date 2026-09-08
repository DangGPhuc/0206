"""
0206 - Analysis Profiles Unit Tests
Phase 34: test_profiles.py
"""
import unittest
from core.profiles import ProfileName, ProfileConfig, get_profile, PROFILES


class TestProfiles(unittest.TestCase):

    def test_all_five_profiles_exist(self):
        expected = ["minimal", "basic", "standard", "advanced", "full"]
        for p in expected:
            prof = get_profile(p)
            self.assertEqual(prof.name.value, p)

    def test_unknown_profile_defaults_to_standard(self):
        prof = get_profile("completely_unknown_profile")
        self.assertEqual(prof.name, ProfileName.STANDARD)

    def test_profile_capabilities(self):
        minimal = get_profile("minimal")
        self.assertFalse(minimal.enable_behavioral)
        self.assertTrue(minimal.force_offline_ai)

        basic = get_profile("basic")
        self.assertTrue(basic.enable_static)
        self.assertTrue(basic.enable_code)
        self.assertTrue(basic.enable_behavioral)

        standard = get_profile("standard")
        self.assertIn("YARA", standard.allowed_integrations)
        self.assertIn("capa", standard.allowed_integrations)

        full = get_profile("full")
        self.assertIn("IDA Pro", full.allowed_integrations)
        self.assertIn("Ghidra", full.allowed_integrations)


if __name__ == "__main__":
    unittest.main()
