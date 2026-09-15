"""Unit tests for the case audit log hash chain (engine.casedb.Case)."""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.casedb import Case                                   # noqa: E402


class AuditChain(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="strata-audit-test-")
        self.addCleanup(lambda: shutil.rmtree(self._dir, ignore_errors=True))
        self.case = Case(os.path.join(self._dir, "case"), name="t",
                         examiner="tester")
        self.addCleanup(self.case.close)

    def test_new_case_starts_with_intact_chain(self):
        self.assertEqual(self.case.verify_audit(),
                         {"intact": True, "broken_at": None})

    def test_chained_entries_verify(self):
        h1 = self.case.log("test.one", {"n": 1})
        h2 = self.case.log("test.two", {"n": 2})
        h3 = self.case.log("test.three", None)
        self.assertTrue(all(hs) for hs in (h1, h2, h3))
        self.assertNotEqual(h1, h2)
        rows = list(reversed(self.case.audit(limit=10)))
        self.assertEqual([r["action"] for r in rows][-3:],
                         ["test.one", "test.two", "test.three"])
        self.assertEqual(rows[-1]["prev_hash"], rows[-2]["hash"])
        self.assertEqual(self.case.verify_audit(),
                         {"intact": True, "broken_at": None})

    def test_tampered_detail_is_detected(self):
        self.case.log("test.one", {"n": 1})
        self.case.log("test.two", {"n": 2})
        self.case.db.execute(
            "UPDATE audit SET detail=? WHERE seq=(SELECT MIN(seq) + 1 "
            "FROM audit)", ('{"tampered": true}',))
        self.case.db.commit()
        self.assertEqual(self.case.verify_audit(),
                         {"intact": False, "broken_at": 2})

    def test_tampered_last_entry_is_detected(self):
        self.case.log("test.one", {"n": 1})
        last = self.case.db.execute(
            "SELECT MAX(seq) FROM audit").fetchone()[0]
        self.case.db.execute(
            "UPDATE audit SET detail=? WHERE seq=?",
            ('{"evil": 1}', last))
        self.case.db.commit()
        self.assertEqual(self.case.verify_audit(),
                         {"intact": False, "broken_at": last})

    def test_deleted_middle_entry_breaks_chain(self):
        self.case.log("test.one", {"n": 1})
        self.case.log("test.two", {"n": 2})
        self.case.log("test.three", {"n": 3})
        self.case.db.execute(
            "DELETE FROM audit WHERE seq=(SELECT MIN(seq) + 1 FROM audit)")
        self.case.db.commit()
        result = self.case.verify_audit()
        self.assertFalse(result["intact"])


if __name__ == "__main__":
    unittest.main()