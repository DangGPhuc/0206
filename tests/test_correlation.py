"""
0206 - Multi-Stage Correlation Engine Unit Tests
Phase 34: test_correlation.py
"""
import unittest
from core.schemas import AnalysisDomain, EvidenceState, Finding, FindingStatus
from core.evidence import EvidenceStore
from core.correlation import CorrelationEngine


class TestCorrelationEngine(unittest.TestCase):

    def test_process_injection_correlation(self):
        store = EvidenceStore()
        e1 = store.create("sample.exe", "IMPORT", "func", "VirtualAllocEx", "PEParser", domain=AnalysisDomain.API)
        e2 = store.create("sample.exe", "IMPORT", "func", "WriteProcessMemory", "PEParser", domain=AnalysisDomain.API)
        e3 = store.create(
            "procmon.csv", "SANDBOX_MEMORY", "remote_write",
            {"source_pid": 111, "target_pid": 222, "bytes": 512},
            "SandboxTelemetry", domain=AnalysisDomain.MEMORY
        )
        e4 = store.create(
            "procmon.csv", "SANDBOX_THREAD", "remote_thread",
            {"source_pid": 111, "target_pid": 222, "start_address": "0x401000"},
            "SandboxTelemetry", domain=AnalysisDomain.THREAD
        )

        inj_finding = Finding(
            finding_id="F-0001",
            domain=AnalysisDomain.PROCESS,
            title="Process Injection Capability",
            details="Potential process injection capability via APIs.",
            state=EvidenceState.INFERRED,
            status=FindingStatus.CAPABILITY,
            confidence=0.7,
            evidence_ids=[e1.evidence_id, e2.evidence_id]
        )

        engine = CorrelationEngine(store)
        findings = engine.correlate([inj_finding])

        f = findings[0]
        self.assertEqual(f.status, FindingStatus.CONFIRMED_BEHAVIOR)
        self.assertIn(e1.evidence_id, f.evidence_ids)
        self.assertIn(e2.evidence_id, f.evidence_ids)
        self.assertIn(e3.evidence_id, f.evidence_ids)
        self.assertIn(e4.evidence_id, f.evidence_ids)

    def test_generic_process_activity_does_not_confirm_injection(self):
        store = EvidenceStore()
        e1 = store.create("sample.exe", "IMPORT", "func", "VirtualAllocEx", "PEParser", domain=AnalysisDomain.API)
        e2 = store.create("sample.exe", "IMPORT", "func", "WriteProcessMemory", "PEParser", domain=AnalysisDomain.API)
        store.create("procmon.csv", "PROCMON_PROCESS", "process_create", "notepad.exe", "Procmon", domain=AnalysisDomain.PROCESS)

        inj_finding = Finding(
            finding_id="F-0001",
            domain=AnalysisDomain.PROCESS,
            title="Process Injection Capability",
            details="Potential process injection capability via APIs.",
            state=EvidenceState.INFERRED,
            status=FindingStatus.CAPABILITY,
            confidence=0.7,
            evidence_ids=[e1.evidence_id, e2.evidence_id]
        )

        result = CorrelationEngine(store).correlate([inj_finding])[0]
        self.assertEqual(result.status, FindingStatus.CAPABILITY)

    def test_persistence_correlation(self):
        store = EvidenceStore()
        e1 = store.create("sample.exe", "STRING", "registry_key", r"Software\Microsoft\Windows\CurrentVersion\Run", "Strings", domain=AnalysisDomain.REGISTRY)
        e2 = store.create("sample.exe", "PROCMON_REGISTRY", "reg_set_value", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\updater", "Procmon", domain=AnalysisDomain.REGISTRY)

        persist_finding = Finding(
            finding_id="F-0002",
            domain=AnalysisDomain.REGISTRY,
            title="Host Persistence Modification",
            details="Potential autostart persistence modification.",
            state=EvidenceState.INFERRED,
            status=FindingStatus.CAPABILITY,
            confidence=0.65,
            evidence_ids=[e1.evidence_id]
        )

        engine = CorrelationEngine(store)
        findings = engine.correlate([persist_finding])

        self.assertEqual(findings[0].status, FindingStatus.CONFIRMED_BEHAVIOR)


    def test_unrelated_registry_activity_does_not_confirm_persistence(self):
        store = EvidenceStore()
        e1 = store.create(
            "sample.exe", "STRING", "registry_key",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "Strings", domain=AnalysisDomain.REGISTRY
        )
        store.create(
            "procmon.csv", "PROCMON_REGISTRY", "reg_set_value",
            r"HKCU\Software\Example\WindowPosition",
            "Procmon", domain=AnalysisDomain.REGISTRY
        )

        persist_finding = Finding(
            finding_id="F-0002",
            domain=AnalysisDomain.REGISTRY,
            title="Host Persistence Modification",
            details="Potential autostart persistence modification.",
            state=EvidenceState.INFERRED,
            status=FindingStatus.CAPABILITY,
            confidence=0.65,
            evidence_ids=[e1.evidence_id]
        )

        result = CorrelationEngine(store).correlate([persist_finding])[0]
        self.assertEqual(result.status, FindingStatus.CAPABILITY)

    def test_unconfirmed_capability_remains_capability(self):
        store = EvidenceStore()
        # Only static import, no runtime execution
        e1 = store.create("sample.exe", "IMPORT", "func", "VirtualAllocEx", "PEParser", domain=AnalysisDomain.API)

        inj_finding = Finding(
            finding_id="F-0003",
            domain=AnalysisDomain.PROCESS,
            title="Process Injection Capability",
            details="Potential process injection capability via APIs.",
            state=EvidenceState.INFERRED,
            status=FindingStatus.CAPABILITY,
            confidence=0.5,
            evidence_ids=[e1.evidence_id]
        )

        engine = CorrelationEngine(store)
        findings = engine.correlate([inj_finding])

        self.assertEqual(findings[0].status, FindingStatus.CAPABILITY)


if __name__ == "__main__":
    unittest.main()
