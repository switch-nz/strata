"""The content index with its text kept compressed (engine.casedb,
engine.textindex).

The compressed layout has to find exactly what the uncompressed one found,
in the same order, and an index built before it must convert without losing
a document -- and stay searchable until it has.
"""

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import casedb, textindex                              # noqa: E402
from engine.casedb import Case                                    # noqa: E402

PART = 2048


def doc(name, body, ev="1", part=PART, kind="file", path=None):
    return (name, path or "/" + name, body, name, part, len(body), 0, "", "",
            kind, ev)


DOCS = [
    doc("report.txt", "quarterly figures and the password reset notes"),
    doc("notes.txt", "nothing of interest in here at all"),
    doc("big.bin", ("filler words " * 20000) + "the password is swordfish "
        + ("trailing words " * 20000)),
    doc("invoice_2021.txt", "see invoice_2021 attached for payment"),
    doc("café.txt", "rendez-vous au café demain"),
    doc("other.txt", "password for the second exhibit", ev="2"),
    doc("Jones letters.txt", "no mention of the name in the text",
        path="/Users/Sam Jones/letters.txt"),
]


def hits(case, terms, **kw):
    r = textindex.query(case, terms, part=PART, evidence="1", **kw)
    return r


def integrity(case):
    case.index.execute("INSERT INTO content_index(content_index, rank) "
                       "VALUES('integrity-check', 1)")


class Compressed(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.case = Case(os.path.join(self.tmp, "c.strata"), name="c")
        self.case.index_add(DOCS)

    def tearDown(self):
        self.case.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_new_case_indexes_compressed(self):
        self.assertEqual(self.case.index_layout, casedb.COMPRESSED)
        self.assertEqual(self.case.index_pending, 0)
        blob = self.case.index.execute(
            "SELECT body FROM content_docs WHERE name='big.bin'").fetchone()[0]
        self.assertIsInstance(blob, bytes)
        self.assertLess(len(blob), 20000)
        integrity(self.case)

    def test_counts_come_from_the_documents_table(self):
        st = textindex.status(self.case, PART, "1")
        self.assertEqual(st["documents"], 6)
        self.assertEqual(st["file_documents"], 6)

    def test_finds_and_scopes_as_before(self):
        r = hits(self.case, ["password"])
        names = [h["name"] for h in r["hits"]]
        self.assertEqual(sorted(names), ["big.bin", "report.txt"])
        self.assertNotIn("other.txt", names)

    def test_snippet_is_cut_around_the_term_deep_in_a_large_document(self):
        r = hits(self.case, ["swordfish"])
        ctx = r["hits"][0]["context"]
        self.assertIn("swordfish", ctx)
        self.assertTrue(ctx.startswith("…") and ctx.endswith("…"))
        self.assertLessEqual(len(ctx.strip("…").split()), 12)

    def test_snippet_at_the_start_of_a_short_document(self):
        ctx = hits(self.case, ["quarterly"])["hits"][0]["context"]
        self.assertTrue(ctx.startswith("quarterly"))

    def test_underscore_separates_tokens_as_fts5_does(self):
        ctx = hits(self.case, ["invoice"])["hits"][0]["context"]
        self.assertIn("invoice_2021", ctx)

    def test_a_match_only_in_the_path_shows_the_opening_words(self):
        r = hits(self.case, ["jones"])
        self.assertEqual([h["name"] for h in r["hits"]],
                         ["Jones letters.txt"])
        self.assertTrue(r["hits"][0]["context"].startswith("no mention"))

    def test_accent_folding_falls_back_to_fts5s_own_snippet(self):
        # unicode61 folds "café" to "cafe"; the passage finder does not, so
        # this hit's snippet comes from FTS5 itself rather than going blank.
        r = hits(self.case, ["cafe"])
        self.assertEqual([h["name"] for h in r["hits"]], ["café.txt"])
        self.assertIn("café", r["hits"][0]["context"])

    def test_removing_some_documents_keeps_the_rest_searchable(self):
        self.case.index_remove("evidence=?", ("2",))
        self.assertEqual(textindex.status(self.case)["documents"], 6)
        r = textindex.query(self.case, ["password"])
        self.assertNotIn("other.txt", [h["name"] for h in r["hits"]])
        integrity(self.case)

    def test_removing_everything_empties_the_index(self):
        self.case.index_remove()
        self.assertEqual(textindex.status(self.case)["documents"], 0)
        integrity(self.case)
        self.case.index_add([doc("again.txt", "password once more")])
        self.assertEqual(
            [h["name"] for h in hits(self.case, ["password"])["hits"]],
            ["again.txt"])

    def test_removing_an_exhibit_removes_its_documents(self):
        self.case.db.execute(
            "INSERT INTO evidence (id, path, added_at) VALUES (2, 'x', 'now')")
        self.case.db.commit()
        gone = self.case.remove_evidence(2)
        self.assertEqual(gone["removed"].get("content_index"), 1)
        self.assertEqual(textindex.status(self.case, PART, "2")["documents"], 0)
        integrity(self.case)

    def test_compact_keeps_every_document(self):
        self.assertTrue(self.case.compact()["compacted"])
        self.assertEqual(textindex.status(self.case)["documents"], 7)
        integrity(self.case)


def plain_index(path, rows):
    db = sqlite3.connect(path)
    db.executescript(casedb.FTS_SCHEMA + casedb.INDEX_META_SCHEMA)
    db.executemany(
        "INSERT INTO content_index (%s) VALUES (%s)"
        % (",".join(casedb.DOC_COLUMNS), ",".join("?" * 11)), rows)
    db.execute("INSERT INTO index_meta VALUES ('index_part_%d', ?)" % PART,
               (str(len(rows)),))
    db.commit()
    db.close()


class Convert(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.folder = os.path.join(self.tmp, "c.strata")
        Case(self.folder, name="c").close()
        index = os.path.join(self.folder, casedb.CACHE_DIR, casedb.INDEX_NAME)
        os.remove(index)
        plain_index(index, DOCS)
        self.case = Case(self.folder)

    def tearDown(self):
        self.case.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def results(self):
        out = {}
        for terms in (["password"], ["swordfish"], ["invoice"], ["jones"],
                      ["cafe"], ["quarterly", "nothing"]):
            out[tuple(terms)] = [
                (h["name"], h["path"], h["node"], h["part"], h["kind"])
                for h in hits(self.case, terms, snippet=False)["hits"]]
        return out

    def test_an_uncompressed_index_is_searchable_until_converted(self):
        self.assertEqual(self.case.index_layout, casedb.PLAIN)
        self.assertEqual(self.case.index_pending, 7)
        self.assertEqual(len(hits(self.case, ["password"])["hits"]), 2)

    def test_conversion_finds_the_same_things_in_the_same_order(self):
        before = self.results()
        r = self.case.relocate_index()
        self.assertEqual(r["moved"], 7)
        self.assertTrue(r["converted"])
        self.assertEqual(self.case.index_layout, casedb.COMPRESSED)
        self.assertEqual(self.case.index_pending, 0)
        self.assertEqual(self.results(), before)
        self.assertEqual(self.case.index.execute(
            "SELECT value FROM index_meta WHERE key=?",
            ("index_part_%d" % PART,)).fetchone()[0], "7")
        integrity(self.case)
        row = self.case.db.execute(
            "SELECT action FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        self.assertEqual(row[0], "index.converted")

    def test_a_reopened_case_stays_converted(self):
        self.case.relocate_index()
        self.case.close()
        self.case = Case(self.folder)
        self.assertEqual(self.case.index_layout, casedb.COMPRESSED)
        self.assertEqual(self.case.index_pending, 0)

    def test_a_failed_conversion_leaves_the_old_index_in_use(self):
        real = Case._build_index_file

        def fail_late(case, source, in_record, dest, progress=None):
            real(case, source, in_record, dest, progress)
            raise sqlite3.OperationalError("database or disk is full")

        with mock.patch.object(Case, "_build_index_file", fail_late):
            r = self.case.relocate_index()
        self.assertEqual(r["moved"], 0)
        self.assertEqual(self.case.index_layout, casedb.PLAIN)
        self.assertEqual(len(hits(self.case, ["password"])["hits"]), 2)
        cache = self.case.cache_dir()
        self.assertEqual([n for n in os.listdir(cache) if n.endswith(".part")],
                         [])

    def test_an_empty_uncompressed_index_is_simply_replaced(self):
        self.case.close()
        index = os.path.join(self.folder, casedb.CACHE_DIR, casedb.INDEX_NAME)
        os.remove(index)
        plain_index(index, [])
        self.case = Case(self.folder)
        self.assertEqual(self.case.index_layout, casedb.COMPRESSED)
        self.assertEqual(self.case.index_pending, 0)


class InRecord(unittest.TestCase):

    def test_an_index_inside_the_record_moves_out_compressed(self):
        tmp = tempfile.mkdtemp()
        try:
            folder = os.path.join(tmp, "c.strata")
            Case(folder, name="c").close()
            db = sqlite3.connect(os.path.join(folder, casedb.DB_NAME))
            db.executescript(casedb.FTS_SCHEMA)
            db.executemany(
                "INSERT INTO content_index (%s) VALUES (%s)"
                % (",".join(casedb.DOC_COLUMNS), ",".join("?" * 11)), DOCS)
            db.commit()
            db.close()
            case = Case(folder)
            try:
                self.assertIs(case.index, case.db)
                self.assertEqual(len(hits(case, ["password"])["hits"]), 2)
                self.assertEqual(case.relocate_index()["moved"], 7)
                self.assertEqual(case.index_layout, casedb.COMPRESSED)
                self.assertEqual(
                    [h["name"] for h in hits(case, ["swordfish"])["hits"]],
                    ["big.bin"])
                left = case.db.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE name='content_index'").fetchall()
                self.assertEqual(left, [])
                integrity(case)
            finally:
                case.close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
