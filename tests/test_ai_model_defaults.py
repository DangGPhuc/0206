"""
Unit and regression tests for AI model configuration defaults,
manifest recording of effective models, and canonical AI transmission boundary.
"""
import unittest
from unittest.mock import patch, MagicMock
import os
import tempfile
from pathlib import Path

from ai.agent import LLMThreatSynthesizer
from ai.schema import SanitizedAIRequest
from core.orchestrator import AnalysisOrchestrator
from core.manifest import AnalysisManifest
from core.evidence import EvidenceStore
from core.schemas import Assessment


class TestAIModelDefaults(unittest.TestCase):

    def setUp(self):
        # Clear AI env vars for predictable testing
        self.orig_env = os.environ.copy()
        for k in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_API_BASE", "OLLAMA_HOST", "OPENAI_MODEL", "ANTHROPIC_MODEL", "OLLAMA_MODEL"]:
            if k in os.environ:
                del os.environ[k]

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)

    def test_openai_default_model(self):
        synth = LLMThreatSynthesizer(provider="openai", api_key="sk-fake", model=None)
        self.assertEqual(synth.model, "gpt-4o")

    def test_anthropic_default_model(self):
        synth = LLMThreatSynthesizer(provider="anthropic", api_key="sk-ant-fake", model=None)
        self.assertEqual(synth.model, "claude-3-5-sonnet-20241022")

    def test_ollama_default_model(self):
        synth = LLMThreatSynthesizer(provider="ollama", api_base="http://localhost:11434", model=None)
        self.assertEqual(synth.model, "llama3")

    def test_regression_anthropic_key_without_model_does_not_use_gpt4o(self):
        """
        Regression test: When ANTHROPIC_API_KEY is present and no model override is passed,
        the effective model must be Claude 3.5 Sonnet and MUST NOT default to 'gpt-4o'.
        """
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-testkey"
        # Auto-detection with model=None
        synth = LLMThreatSynthesizer(provider="auto", model=None)
        self.assertEqual(synth.provider, "anthropic")
        self.assertNotEqual(synth.model, "gpt-4o")
        self.assertEqual(synth.model, "claude-3-5-sonnet-20241022")

    def test_orchestrator_preserves_provider_default_when_model_is_none(self):
        """AnalysisOrchestrator default model=None allows provider to choose its default."""
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-testkey"
        orch = AnalysisOrchestrator()
        fixture_exe = Path(__file__).parent / "sample_benign_triage.exe"

        with tempfile.TemporaryDirectory() as tmp_dir:
            # Mock LLMThreatSynthesizer to avoid actual network call
            with patch("core.orchestrator.LLMThreatSynthesizer") as mock_synth_cls:
                mock_inst = MagicMock()
                mock_inst.provider = "anthropic"
                mock_inst.model = "claude-3-5-sonnet-20241022"

                mock_inst.synthesize.return_value = Assessment(
                    assessment_id="A-TEST",
                    title="Test",
                    threat_level="INFORMATIONAL",
                    threat_score=0,
                    classification="BENIGN",
                    summary="Test summary"
                )
                mock_synth_cls.return_value = mock_inst

                res = orch.run(
                    sample_path=fixture_exe,
                    output_dir=tmp_dir,
                    profile="minimal",
                    offline=False,
                    model=None  # Explicitly None (default)
                )

                # Verify LLMThreatSynthesizer was initialized with model=None
                mock_synth_cls.assert_called_once()
                call_kwargs = mock_synth_cls.call_args[1]
                self.assertIsNone(call_kwargs.get("model"))

                # Verify manifest recorded effective model
                self.assertEqual(res.manifest.synthesizer["model"], "claude-3-5-sonnet-20241022")
                self.assertEqual(res.manifest.ai_metadata["model"], "claude-3-5-sonnet-20241022")

    def test_only_sanitized_ai_request_crosses_ai_boundary(self):
        """
        Confirms canonical boundary: AI provider receives ONLY SanitizedAIRequest,
        and orchestrator does not perform duplicate raw-evidence transmission audits.
        """
        synth = LLMThreatSynthesizer(provider="anthropic", api_key="sk-ant-fake", model=None)
        store = EvidenceStore()
        store.create("sample.exe", "STATIC", "import", "VirtualAlloc", "test")

        # Mock provider synthesize
        synth.provider_instance.is_available = MagicMock(return_value=True)
        synth.provider_instance.synthesize = MagicMock(return_value={
            "executive_summary": "Test synthesis",
            "threat_classification": "BENIGN",
            "hypotheses": [],
            "recommended_actions": [],
            "cited_evidence_ids": ["E-0001"]
        })

        with patch.object(synth.privacy_redactor, "audit_for_transmission", wraps=synth.privacy_redactor.audit_for_transmission) as mock_audit:
            assessment = synth.synthesize(store)

            # Check that audit_for_transmission was called on SanitizedAIRequest.model_dump()
            self.assertTrue(mock_audit.called)
            audited_dict = mock_audit.call_args[0][0]
            self.assertIn("system_prompt", audited_dict)
            self.assertIn("user_prompt", audited_dict)
            self.assertIn("evidence_records", audited_dict)

            # Check that provider received SanitizedAIRequest instance
            synth.provider_instance.synthesize.assert_called_once()
            req_arg = synth.provider_instance.synthesize.call_args[1].get("request")
            self.assertIsInstance(req_arg, SanitizedAIRequest)


if __name__ == "__main__":
    unittest.main()
