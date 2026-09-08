"""
0206 - Selftest Diagnostic Unit Tests
Phase 34: test_selftest.py
"""
import unittest
from io import StringIO
from rich.console import Console
from core.selftest import run_selftest


class TestSelfTestModule(unittest.TestCase):

    def test_selftest_passes_completely(self):
        buf = StringIO()
        test_console = Console(file=buf, force_terminal=False)
        result = run_selftest(test_console)
        output = buf.getvalue()
        self.assertTrue(result)
        self.assertIn("Core Dependencies", output)
        self.assertIn("PEStaticAnalyzer", output)
        self.assertIn("FindingEngine", output)


if __name__ == "__main__":
    unittest.main()
