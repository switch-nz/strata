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


    def last_seq(self):
        return self.case.db.execute("SELECT MAX(seq) FROM audit").fetchone()[0]

    def test_entries_cut_from_the_end_are_detected(self):
        self.case.log("test.one", {"n": 1})
        self.case.log("test.two", {"n": 2})
        last = self.last_seq()
        self.case.db.execute("DELETE FROM audit WHERE seq=?", (last,))
        self.case.db.commit()
        got = self.case.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], last)
        self.assertIn("removed from the end", got["detail"])

    def test_truncation_stays_visible_after_more_entries(self):
        self.case.log("test.one", {"n": 1})
        self.case.log("test.two", {"n": 2})
        last = self.last_seq()
        self.case.db.execute("DELETE FROM audit WHERE seq=?", (last,))
        self.case.db.commit()
        self.case.log("test.three", {"n": 3})
        got = self.case.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], self.last_seq())

    def test_emptied_log_is_detected(self):
        self.case.log("test.one", {"n": 1})
        self.case.db.execute("DELETE FROM audit")
        self.case.db.commit()
        self.assertFalse(self.case.verify_audit()["intact"])

    def test_entries_appended_outside_strata_are_detected(self):
        self.case.log("test.one", {"n": 1})
        row = self.case.db.execute(
            "SELECT * FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        import hashlib
        at, ex, action, detail = "2030-01-01T00:00:00Z", "x", "forged", "{}"
        h = hashlib.sha256(("%s|%s|%s|%s|%s" % (row["hash"], at, ex, action,
                                                detail)).encode()).hexdigest()
        self.case.db.execute(
            "INSERT INTO audit (at, examiner, action, detail, prev_hash, "
            "hash) VALUES (?,?,?,?,?,?)", (at, ex, action, detail,
                                           row["hash"], h))
        self.case.db.commit()
        got = self.case.verify_audit()
        self.assertFalse(got["intact"])
        self.assertEqual(got["broken_at"], row["seq"] + 1)

    def test_case_without_a_recorded_head_still_verifies(self):
        # Cases written before the head was recorded.
        self.case.log("test.one", {"n": 1})
        self.case.db.execute("DELETE FROM meta WHERE key='audit_head'")
        self.case.db.commit()
        self.assertEqual(self.case.verify_audit(),
                         {"intact": True, "broken_at": None})
        self.case.log("test.two", {"n": 2})
        self.assertEqual(self.case.verify_audit(),
                         {"intact": True, "broken_at": None})


WRITER = r"""
import sys
sys.path.insert(0, sys.argv[1])
from engine.casedb import Case
c = Case(sys.argv[2], examiner=sys.argv[3])
for i in range(int(sys.argv[4])):
    c.log("concurrent.write", {"i": i})
c.close()
"""


class ConcurrentWriters(unittest.TestCase):
    """Two Strata processes on one case folder: the in-process lock does not
    reach across them, so the chain must not fork."""

    def test_two_processes_logging_at_once_keep_one_chain(self):
        import subprocess
        d = tempfile.mkdtemp(prefix="strata-audit-mp-")
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        path = os.path.join(d, "case")
        Case(path, name="t", examiner="setup").close()
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        procs = [subprocess.Popen([sys.executable, "-c", WRITER, root, path,
                                   who, "150"])
                 for who in ("a", "b", "c")]
        for p in procs:
            self.assertEqual(p.wait(timeout=120), 0)
        case = Case(path)
        self.addCleanup(case.close)
        n = case.db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        self.assertEqual(n, 1 + 3 * 150)
        self.assertEqual(case.verify_audit(),
                         {"intact": True, "broken_at": None})

if __name__ == "__main__":
    unittest.main()