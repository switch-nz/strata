"""Case notes (engine.casedb.Case): attributed, versioned, never changed in
place, and carried into the report."""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import report                                        # noqa: E402
from engine.casedb import Case                                   # noqa: E402


class CaseNotes(unittest.TestCase):

    def setUp(self):
        d = tempfile.mkdtemp(prefix="strata-notes-test-")
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        self.path = os.path.join(d, "case")
        self.alice = Case(self.path, name="t", examiner="Alice")
        self.addCleanup(self.alice.close)

    def other(self, who):
        c = Case(self.path, examiner=who)
        self.addCleanup(c.close)
        return c

    def test_a_note_names_its_writer_and_time(self):
        nid = self.alice.add_note("  Suspect USB first seen 14:02.  ")
        [n] = self.alice.notes()
        self.assertEqual(n["id"], nid)
        self.assertEqual(n["body"], "Suspect USB first seen 14:02.")
        self.assertEqual(n["author"], "Alice")
        self.assertTrue(n["created_at"].endswith("Z"))
        self.assertEqual(n["history"], [])

    def test_empty_note_is_refused(self):
        with self.assertRaises(ValueError):
            self.alice.add_note("   ")
        self.assertEqual(self.alice.notes(), [])

    def test_an_edit_by_someone_else_keeps_both_names_and_both_texts(self):
        nid = self.alice.add_note("first reading")
        bob = self.other("Bob")
        new = bob.edit_note(nid, "second reading")
        self.assertNotEqual(new, nid)
        [n] = self.alice.notes()
        self.assertEqual(n["body"], "second reading")
        self.assertEqual(n["examiner"], "Bob")
        self.assertEqual(n["author"], "Alice")
        self.assertEqual([(h["examiner"], h["body"]) for h in n["history"]],
                         [("Alice", "first reading")])

    def test_only_the_current_version_can_be_edited(self):
        nid = self.alice.add_note("v1")
        self.other("Bob").edit_note(nid, "v2 from Bob")
        # Carol's screen still shows v1: her edit must not silently win.
        self.assertIsNone(self.other("Carol").edit_note(nid, "v2 from Carol"))
        self.assertEqual(self.alice.notes()[0]["body"], "v2 from Bob")

    def test_unchanged_edit_adds_no_version(self):
        nid = self.alice.add_note("same")
        self.assertEqual(self.alice.edit_note(nid, "same"), nid)
        self.assertEqual(self.alice.notes()[0]["history"], [])

    def test_withdrawn_note_stays_on_the_record(self):
        nid = self.alice.add_note("wrong exhibit")
        self.assertTrue(self.other("Bob").retract_note(nid))
        self.assertEqual(self.alice.notes(), [])
        [n] = self.alice.notes(include_retracted=True)
        self.assertEqual(n["retracted_by"], "Bob")
        self.assertFalse(self.alice.retract_note(nid))
        self.assertIsNone(self.alice.edit_note(nid, "revive"))

    def test_every_change_is_in_the_audit_log(self):
        nid = self.alice.add_note("a")
        self.alice.edit_note(nid, "b")
        self.alice.retract_note(nid + 1)
        actions = [r["action"] for r in self.alice.audit()]
        for a in ("note.add", "note.edit", "note.retract"):
            self.assertIn(a, actions)
        self.assertTrue(self.alice.verify_audit()["intact"])

    def test_pulse_counts_notes_so_other_examiners_refresh(self):
        before = self.alice.pulse()["notes"]
        self.other("Bob").add_note("from Bob")
        self.assertEqual(self.alice.pulse()["notes"], before + 1)

    def test_report_prints_notes_with_writers_versions_and_withdrawals(self):
        nid = self.alice.add_note("kept <b>as</b> text")
        self.other("Bob").edit_note(nid, "revised by Bob")
        gone = self.alice.add_note("withdrawn one")
        self.alice.retract_note(gone)
        html = report.render(self.alice.report())
        self.assertIn("revised by Bob", html)
        self.assertIn("kept &lt;b&gt;as&lt;/b&gt; text", html)
        self.assertIn("withdrawn one", html)
        self.assertIn("Withdrawn by Alice", html)
        self.assertIn("Case notes", html)


    def test_withdrawal_and_edit_change_the_pulse_revision(self):
        nid = self.alice.add_note("a")
        p0 = self.alice.pulse()
        self.other("Bob").edit_note(nid, "b")
        p1 = self.alice.pulse()
        # An edit is a new version, not a new item.
        self.assertEqual(p1["notes"], p0["notes"])
        self.assertNotEqual(p1["notes_rev"], p0["notes_rev"])
        self.other("Bob").retract_note(nid + 1)
        p2 = self.alice.pulse()
        self.assertNotEqual(p2["notes_rev"], p1["notes_rev"])

    def test_overlong_note_is_refused_not_cut(self):
        with self.assertRaises(ValueError):
            self.alice.add_note("x" * (Case.NOTE_MAX + 1))
        nid = self.alice.add_note("short")
        with self.assertRaises(ValueError):
            self.alice.edit_note(nid, "y" * (Case.NOTE_MAX + 1))
        self.assertEqual(self.alice.notes()[0]["body"], "short")

    def test_report_dates_the_current_version_and_keeps_line_breaks(self):
        nid = self.alice.add_note("line one\nline two")
        self.other("Bob").edit_note(nid, "replaced")
        html = report.render(self.alice.report())
        self.assertIn("This version by Bob", html)
        self.assertIn('<div class="pre note">line one\nline two</div>', html)


RACER = r"""
import sys, time
sys.path.insert(0, sys.argv[1])
from engine import casedb
path, who, nid, go = sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
orig = casedb.Case._current_note
def slow(self, n):
    row = orig(self, n)
    time.sleep(0.5)      # widen the gap between the check and the write
    return row
casedb.Case._current_note = slow
c = casedb.Case(path, examiner=who)
while not __import__("os").path.exists(go):
    time.sleep(0.01)
print(c.edit_note(nid, who + "'s version"))
c.close()
"""


class ConcurrentEditors(unittest.TestCase):
    """Two Strata processes editing one note: only one edit may win."""

    def test_two_processes_cannot_fork_a_note(self):
        import subprocess
        d = tempfile.mkdtemp(prefix="strata-notes-mp-")
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        path = os.path.join(d, "case")
        c = Case(path, name="t", examiner="setup")
        nid = c.add_note("original")
        c.close()
        go = os.path.join(d, "go")
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        procs = [subprocess.Popen([sys.executable, "-c", RACER, root, path,
                                   who, str(nid), go],
                                  stdout=subprocess.PIPE, text=True)
                 for who in ("Alice", "Bob")]
        open(go, "w").close()
        outs = [p.communicate(timeout=60)[0].strip() for p in procs]
        self.assertEqual(sorted(o == "None" for o in outs), [False, True])
        c = Case(path)
        self.addCleanup(c.close)
        self.assertEqual(len(c.notes()), 1)


if __name__ == "__main__":
    unittest.main()
