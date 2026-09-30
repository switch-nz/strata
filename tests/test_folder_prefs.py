"""Preferences kept in the case (folder columns) and the search filters:
what is stored is checked on the way in and on the way out, a case shares
its columns with whoever opens it, and a filter that could not mean anything
is refused instead of quietly matching everything."""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import casedb, casepref, filesearch                   # noqa: E402
import test_notes_api                                              # noqa: E402
from test_notes_api import Client                                 # noqa: E402
import imagebuild_fat                                              # noqa: E402


def setUpModule():
    # The server records the address it was started on, so a server another
    # test module started earlier stops answering once a later one starts.
    # This module gets its own, started when its first client asks.
    test_notes_api._PORT.clear()


class CleanColumns(unittest.TestCase):

    def test_a_list_of_known_columns_keeps_its_order_and_drops_repeats(self):
        self.assertEqual(
            casepref.clean_folder_columns(["modified", "size", "modified"]),
            ["modified", "size"])

    def test_none_means_the_default_and_an_empty_list_means_no_columns(self):
        self.assertIsNone(casepref.clean_folder_columns(None))
        self.assertEqual(casepref.clean_folder_columns([]), [])

    def test_unknown_names_and_non_lists_are_refused(self):
        for bad in (["size", "bogus"], "size", {"size": 1}, [1], [["size"]],
                    5, True):
            with self.assertRaises(ValueError):
                casepref.clean_folder_columns(bad)

    def test_what_a_case_holds_is_checked_when_read_back(self):
        for raw in (None, "", "not json", "5", '["bogus"]', '{"a": 1}'):
            self.assertIsNone(casepref.load_folder_columns(raw), raw)
        self.assertEqual(casepref.load_folder_columns('["size", "sha"]'),
                         ["size", "sha"])

    def test_the_default_is_every_column(self):
        self.assertEqual(sorted(casepref.DEFAULT_FOLDER_COLUMNS),
                         sorted(casepref.FOLDER_COLUMNS))


class CaseStorage(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-prefs-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.path = os.path.join(self.dir, "c.strata")

    def open(self):
        case = casedb.Case(self.path, examiner="Alice")
        self.addCleanup(case.close)
        return case

    def test_columns_persist_with_the_case_and_can_be_reset(self):
        a = self.open()
        self.assertIsNone(a.folder_columns())
        self.assertEqual(a.set_folder_columns(["size", "modified"]),
                         ["size", "modified"])
        a.close()
        b = self.open()
        self.assertEqual(b.folder_columns(), ["size", "modified"])
        self.assertIsNone(b.set_folder_columns(None))
        self.assertIsNone(b.folder_columns())

    def test_a_bad_choice_is_refused_and_the_old_one_kept(self):
        a = self.open()
        a.set_folder_columns(["size"])
        with self.assertRaises(ValueError):
            a.set_folder_columns(["size", "nope"])
        self.assertEqual(a.folder_columns(), ["size"])

    def test_a_display_choice_is_not_an_audit_entry(self):
        a = self.open()
        before = len(a.audit())
        a.set_folder_columns(["size"])
        self.assertEqual(len(a.audit()), before)

    def test_a_hand_edited_value_reads_as_no_choice(self):
        a = self.open()
        a._set(casepref.meta_key("folder_columns"), '["bogus"]')
        a.db.commit()
        self.assertIsNone(a.folder_columns())


class ColumnsApi(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-prefs-api-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.c = Client()
        self.c.call("GET", "/")

    def new_case(self, name):
        status, _ = self.c.call("POST", "/api/case/new", {
            "path": os.path.join(self.dir, name), "name": name,
            "examiner": "Alice"})
        self.assertEqual(status, 200)
        return self.c.call("GET", "/api/case/prefs")[1]["case"]

    def test_the_columns_are_the_cases_and_work_without_an_exhibit(self):
        case = self.new_case("a")
        _, r = self.c.call("GET", "/api/case/prefs")
        self.assertIsNone(r["folder_columns"])
        self.assertEqual(r["folder_columns_default"],
                         list(casepref.DEFAULT_FOLDER_COLUMNS))
        status, r = self.c.call("POST", "/api/case/prefs", {
            "case": case, "folder_columns": ["size", "created"]})
        self.assertEqual(status, 200, r)
        self.assertEqual(self.c.call("GET", "/api/case/prefs")[1]
                         ["folder_columns"], ["size", "created"])
        other = self.new_case("b")
        self.assertIsNone(self.c.call("GET", "/api/case/prefs")[1]
                          ["folder_columns"])
        self.assertNotEqual(case, other)

    def test_a_page_showing_another_case_does_not_change_this_one(self):
        a = self.new_case("a")
        self.new_case("b")
        status, r = self.c.call("POST", "/api/case/prefs", {
            "case": a, "folder_columns": ["size"]})
        self.assertEqual(status, 409)
        status, _ = self.c.call("POST", "/api/case/prefs",
                                {"folder_columns": ["size"]})
        self.assertEqual(status, 409)
        self.assertIsNone(self.c.call("GET", "/api/case/prefs")[1]
                          ["folder_columns"])

    def test_bad_requests_are_refused_and_change_nothing(self):
        case = self.new_case("a")
        self.c.call("POST", "/api/case/prefs",
                    {"case": case, "folder_columns": ["size"]})
        for body in ({"case": case, "folder_columns": ["size", "bogus"]},
                     {"case": case, "folder_columns": "size"},
                     {"case": case}):
            status, r = self.c.call("POST", "/api/case/prefs", body)
            self.assertEqual(status, 400, body)
            self.assertIn("error", r)
        self.assertEqual(self.c.call("GET", "/api/case/prefs")[1]
                         ["folder_columns"], ["size"])
        status, _ = self.c.call("POST", "/api/case/prefs", {
            "case": case, "folder_columns": None})
        self.assertEqual(status, 200)
        self.assertIsNone(self.c.call("GET", "/api/case/prefs")[1]
                          ["folder_columns"])

    def test_no_case_open_is_an_error_not_a_default(self):
        c = Client()
        c.call("GET", "/")
        status, r = c.call("GET", "/api/case/prefs")
        self.assertEqual(status, 400)


def entry(name, **kw):
    return dict({"name": name, "size": 10, "is_dir": False}, **kw)


class Filters(unittest.TestCase):

    def test_the_folder_filter_controls_are_all_understood(self):
        f = filesearch.clean_filters({
            "name": " report ", "extensions": [".PDF", "docx", ""],
            "min_size": 1, "max_size": 100,
            "modified_after": "2024-01-01", "modified_before":
            "2024-02-01T23:59:59Z", "created_after": "2024-01-01",
            "accessed_before": "2024-03-01", "hide_deleted": True,
            "files_only": True})
        self.assertEqual(f["name"], "report")
        self.assertEqual(f["extensions"], ["pdf", "docx"])
        self.assertTrue(f["hide_deleted"])

    def test_off_and_empty_filters_are_dropped(self):
        self.assertIsNone(filesearch.clean_filters(None))
        self.assertIsNone(filesearch.clean_filters({}))
        self.assertIsNone(filesearch.clean_filters({
            "name": "  ", "extensions": [], "min_size": None,
            "deleted_only": False}))

    def test_nonsense_is_refused_rather_than_ignored(self):
        for bad in ([], "x", {"nam": "x"}, {"name": 5}, {"extensions": "pdf"},
                    {"extensions": [5]}, {"min_size": -1}, {"min_size": 1.5},
                    {"min_size": "1"}, {"min_size": True},
                    {"modified_after": "yesterday"}, {"modified_after": 5},
                    {"deleted_only": "yes"}, {"deleted_only": 1},
                    {"name": "x" * 300},
                    {"extensions": ["a"] * 65}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                filesearch.clean_filters(bad)

    def test_filters_that_can_match_nothing_are_refused(self):
        for bad in ({"deleted_only": True, "hide_deleted": True},
                    {"min_size": 10, "max_size": 5},
                    {"created_after": "2024-05-01",
                     "created_before": "2024-01-01"}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                filesearch.clean_filters(bad)

    def test_name_created_accessed_and_hide_deleted_filter_entries(self):
        rows = [
            entry("Report.docx", created="2024-02-01T10:00:00Z",
                  accessed="2024-03-05T10:00:00Z"),
            entry("notes.txt", created="2023-01-01T10:00:00Z", deleted=True),
            entry("dir", is_dir=True),
        ]

        def names(f):
            f = filesearch.clean_filters(f)
            return [e["name"] for e in rows
                    if filesearch.matches_filters(e, f)]

        self.assertEqual(names({"name": "REPORT"}), ["Report.docx"])
        self.assertEqual(names({"hide_deleted": True}),
                         ["Report.docx", "dir"])
        self.assertEqual(names({"deleted_only": True}), ["notes.txt"])
        self.assertEqual(names({"created_after": "2024-01-01"}),
                         ["Report.docx"])
        self.assertEqual(names({"created_before": "2023-12-31T23:59:59Z"}),
                         ["notes.txt"])
        self.assertEqual(names({"accessed_after": "2024-03-01"}),
                         ["Report.docx"])
        # An entry with no accessed time cannot be shown to be after one.
        self.assertEqual(names({"accessed_before": "2024-12-31"}),
                         ["Report.docx"])
        self.assertEqual(names({"files_only": True}),
                         ["Report.docx", "notes.txt"])


class SearchRoutes(unittest.TestCase):
    """The search, index and hash routes refuse a bad filter before starting
    anything."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-filters-api-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        img = os.path.join(self.dir, "d.img")
        with open(img, "wb") as fh:
            fh.write(imagebuild_fat.build_fat(16))
        self.c = Client()
        self.c.call("GET", "/")
        status, r = self.c.call("POST", "/api/open", {
            "path": img, "case_path": os.path.join(self.dir, "c.strata"),
            "examiner": "Alice"})
        self.assertEqual(status, 200, r)

    def test_bad_filters_are_a_400_on_every_route_that_takes_them(self):
        for path, body in (
                ("/api/search/files", {"terms": ["a"], "part": 0}),
                ("/api/search/index", {"part": 0}),
                ("/api/hash", {"part": 0})):
            for bad in ({"nam": "x"}, {"deleted_only": True,
                                       "hide_deleted": True}):
                status, r = self.c.call("POST", path,
                                        dict(body, filters=bad))
                self.assertEqual(status, 400, (path, bad, r))
                self.assertIn("error", r)

    def test_a_good_filter_still_starts_the_search(self):
        status, r = self.c.call("POST", "/api/search/files", {
            "terms": ["a"], "part": 0,
            "filters": {"hide_deleted": True, "name": "txt"}})
        self.assertEqual(status, 200, r)


if __name__ == "__main__":
    unittest.main()
