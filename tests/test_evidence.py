"""
0206 - Evidence Store & Graph Unit Tests
Phase 34: test_evidence.py
"""
import unittest
import tempfile
import os
from pathlib import Path
from core.schemas import AnalysisDomain, EvidenceState, EvidenceRecord
from core.evidence import EvidenceStore, MemoryEvidenceBackend, SQLiteEvidenceBackend, calculate_fingerprint


class TestEvidenceModel(unittest.TestCase):

    def test_fingerprint_calculation(self):
        fp1 = calculate_fingerprint("FILE_METADATA", "sha256", "abc12345", "art_sha")
        fp2 = calculate_fingerprint("FILE_METADATA", "sha256", "abc12345", "art_sha")
        fp3 = calculate_fingerprint("FILE_METADATA", "sha256", "different", "art_sha")
        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)

    def test_memory_store_deduplication(self):
        store = EvidenceStore(backend=MemoryEvidenceBackend())
        r1 = store.create("sample.exe", "IMPORT", "func", "VirtualAlloc", "PEParser", domain=AnalysisDomain.API)
        r2 = store.create("sample.exe", "IMPORT", "func", "VirtualAlloc", "PEParser", domain=AnalysisDomain.API)
        self.assertEqual(r1.evidence_id, r2.evidence_id)
        self.assertEqual(r2.duplicate_count, 2)
        self.assertEqual(len(store), 1)

    def test_sqlite_store_crud(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = EvidenceStore(backend="sqlite", db_path=db_path)
            r = store.create("sample.exe", "SECTION", "name", ".text", "PEParser", domain=AnalysisDomain.PE)
            self.assertEqual(store.get(r.evidence_id).value, ".text")
            all_recs = store.all()
            self.assertEqual(len(all_recs), 1)
            by_dom = store.find_by_domain(AnalysisDomain.PE)
            self.assertEqual(len(by_dom), 1)
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_evidence_derivation_lineage(self):
        store = EvidenceStore()
        e1 = store.create("sample.exe", "FILE", "sha256", "deadbeef", "Hasher", domain=AnalysisDomain.PE)
        e2 = store.create(
            "sample.exe", "API_HASH", "constant", "0x382C0F97", "Scanner",
            domain=AnalysisDomain.OBFUSCATION,
            parent_evidence_ids=[e1.evidence_id],
            derivation_rule="R-HASH-01"
        )
        e3 = store.create(
            "sample.exe", "RESOLVED_API", "name", "VirtualAlloc", "Resolver",
            domain=AnalysisDomain.API,
            parent_evidence_ids=[e2.evidence_id],
            derivation_rule="R-RESOLVE-01"
        )

        parents = store.get_parents(e3.evidence_id)
        self.assertEqual(len(parents), 1)
        self.assertEqual(parents[0].evidence_id, e2.evidence_id)

        children = store.get_children(e1.evidence_id)
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].evidence_id, e2.evidence_id)

        lineage = store.get_lineage(e3.evidence_id)
        self.assertEqual(lineage["evidence_id"], e3.evidence_id)
        self.assertEqual(len(lineage["parents"]), 1)
        self.assertEqual(lineage["parents"][0]["evidence_id"], e2.evidence_id)


if __name__ == "__main__":
    unittest.main()
