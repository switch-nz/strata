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


if __name__ == "__main__":
    unittest.main()
