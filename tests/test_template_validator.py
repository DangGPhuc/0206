"""
Unit Tests for 0206 Template Validator Module
"""
import unittest
import tempfile
from pathlib import Path
from report.template_validator import TemplateValidator


class TestTemplateValidator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_template(self):
        bogus_path = Path(self.temp_dir.name) / "non_existent.docx"
        valid, warnings = TemplateValidator.validate_sans_style_template(bogus_path)
        self.assertFalse(valid)
        self.assertTrue(any("does not exist" in w for w in warnings))

    def test_invalid_extension(self):
        bad_file = Path(self.temp_dir.name) / "template.txt"
        bad_file.write_text("not a docx")
        valid, warnings = TemplateValidator.validate_sans_style_template(bad_file)
        self.assertFalse(valid)
        self.assertTrue(any(".docx" in w for w in warnings))


if __name__ == "__main__":
    unittest.main()
