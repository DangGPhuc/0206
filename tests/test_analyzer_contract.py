"""
Tests for Phase 4 & 6: AnalyzerContract, stages, safety levels, and reputation providers.
"""
import pytest
from analyzers.contract import AnalyzerContract, AnalysisStage, AnalyzerSafetyLevel
from analyzers.static.pe_analyzer import PEStaticAnalyzer
from analyzers.code.capstone_triage import CodeAnalyzer
from analyzers.behavioral.event_normalizer import EventNormalizer
from analyzers.network.pcap_analyzer import PCAPAnalyzer
from analyzers.anti_analysis.anti_analysis_analyzer import AntiAnalysisAnalyzer
from analyzers.unpacking.unpacking_analyzer import UnpackingAnalyzer
from analyzers.dotnet.dotnet_analyzer import DotNetAnalyzer
from analyzers.shellcode.shellcode_analyzer import ShellcodeAnalyzer
from analyzers.documents.document_analyzer import DocumentAnalyzer
from analyzers.reputation import (
    VirusTotalReputationProvider,
    MalwareBazaarReputationProvider,
    ThreatFoxReputationProvider,
    ReputationStatus
)
from core.schemas import AnalysisDomain


def test_analyzer_contract_compliance():
    """All core analyzers must strictly implement AnalyzerContract and declare stage and domains."""
    analyzers = [
        PEStaticAnalyzer(),
        CodeAnalyzer(),
        EventNormalizer(),
        PCAPAnalyzer(),
        AntiAnalysisAnalyzer(),
        UnpackingAnalyzer(),
        DotNetAnalyzer(),
        ShellcodeAnalyzer(),
        DocumentAnalyzer(),
    ]

    for a in analyzers:
        assert isinstance(a, AnalyzerContract), f"{a.__class__.__name__} must subclass AnalyzerContract"
        assert a.name, f"{a.__class__.__name__} must have a name"
        assert a.domains, f"{a.__class__.__name__} must declare at least one domain"
        assert isinstance(a.stage, AnalysisStage), f"{a.__class__.__name__} stage must be an AnalysisStage"
        assert isinstance(a.safety_level, AnalyzerSafetyLevel)
        assert isinstance(a.resource_limits, dict)

    # Verify stage distribution
    pe = PEStaticAnalyzer()
    assert pe.stage == AnalysisStage.BASIC_STATIC
    assert AnalysisDomain.PE in pe.domains

    beh = EventNormalizer()
    assert beh.stage == AnalysisStage.BASIC_DYNAMIC

    anti = AntiAnalysisAnalyzer()
    assert anti.stage == AnalysisStage.ADVANCED_STATIC
    assert AnalysisDomain.ANTI_ANALYSIS in anti.domains


def test_reputation_providers_offline():
    """Reputation providers must handle offline mode cleanly without throwing or uploading."""
    providers = [
        VirusTotalReputationProvider(offline=True),
        MalwareBazaarReputationProvider(offline=True),
        ThreatFoxReputationProvider(offline=True),
    ]

    dummy_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR MD5

    for p in providers:
        assert p.name
        res = p.lookup_hash(dummy_hash)
        assert res.status in (ReputationStatus.SKIPPED_OFFLINE, ReputationStatus.NOT_CHECKED)
        assert "offline" in res.details.lower() or "skipped" in res.details.lower()
        # Verify NOT_FOUND is distinct from clean
        assert res.status != ReputationStatus.NOT_FOUND
