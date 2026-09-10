"""
0206 - CLI Subcommands & Argument Parsing Unit Tests
Phase 34: test_cli.py
"""
import unittest
import subprocess
import sys
from pathlib import Path


class TestCLICommands(unittest.TestCase):

    def test_cli_help(self):
        proc = subprocess.run([sys.executable, "main.py", "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("analyze", proc.stdout)
        self.assertIn("doctor", proc.stdout)
        self.assertIn("capabilities", proc.stdout)
        self.assertIn("selftest", proc.stdout)

    def test_cli_doctor_command(self):
        proc = subprocess.run([sys.executable, "main.py", "doctor"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Doctor Diagnosis Summary", proc.stdout)

    def test_cli_capabilities_command(self):
        proc = subprocess.run([sys.executable, "main.py", "capabilities"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("CORE Tier 1 Packages", proc.stdout)

    def test_cli_selftest_command(self):
        proc = subprocess.run([sys.executable, "main.py", "selftest"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("All Self-Tests Passed", proc.stdout)

    def test_cli_analyze_help(self):
        proc = subprocess.run([sys.executable, "main.py", "analyze", "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--profile", proc.stdout)
        self.assertIn("--offline", proc.stdout)
        self.assertIn("--adaptive", proc.stdout)

    def test_cli_sandbox_smoke_test_not_run_when_no_vm(self):
        proc = subprocess.run(
            [sys.executable, "main.py", "sandbox", "smoke-test", "--backend", "virtualbox"],
            capture_output=True,
            text=True
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("REAL_VM_SMOKE_TEST=NOT_RUN", proc.stdout)

    def test_cli_lab_provision_flags(self):
        proc = subprocess.run([sys.executable, "main.py", "lab", "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--target-dir", proc.stdout)
        self.assertIn("--output", proc.stdout)


if __name__ == "__main__":
    unittest.main()
