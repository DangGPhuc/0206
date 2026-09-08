"""
Unit tests for Doctor and Self-test modules.
"""
import unittest
from io import StringIO
from rich.console import Console

from core.doctor import run_doctor
from core.selftest import run_selftest


class TestDoctorAndSelfTest(unittest.TestCase):

    def setUp(self):
        self.console = Console(file=StringIO(), force_terminal=False)

    def test_run_doctor(self):
        core_ok = run_doctor(self.console)
        # Core packages should be available in this environment
        self.assertTrue(core_ok)

    def test_run_selftest(self):
        passed = run_selftest(self.console)
        self.assertTrue(passed)


if __name__ == "__main__":
    unittest.main()
