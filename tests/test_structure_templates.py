"""Structure templates an examiner writes (engine.structure, kept in the
case): every field is checked before it is stored or applied, a template is
shared with whoever opens the case, edits cannot overwrite each other
unseen, what is deleted stays in the audit log, and a preview applies a
template to the bytes at an offset without saving it."""

import copy
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import casedb, structure                               # noqa: E402
import test_notes_api                                              # noqa: E402
from test_notes_api import Client                                  # noqa: E402
import imagebuild_fat                                              # noqa: E402


def setUpModule():
    # The server records the address it was started on, so a server another
    # test module started earlier stops answering once a later one starts.
    # This module gets its own, started when its first client asks.
    test_notes_api._PORT.clear()


def field(offset, size, name, kind, note=""):
    return {"offset": offset, "size": size, "name": name, "kind": kind,
            "note": note}


def tpl(name="Header", *fields):
    return {"name": name, "description": "d",
            "fields": list(fields) or [field(0, 4, "Magic", "ascii"),
                                       field(4, 2, "Version", "u16")]}


class Validate(unittest.TestCase):

    def bad(self, t, text=None):
        with self.assertRaises(ValueError) as cm:
            structure.validate_template(t)
        if text:
            self.assertIn(text, str(cm.exception))

    def test_a_good_template_is_normalised(self):
        t = structure.validate_template({
            "name": "  Header ", "fields": [
                {"offset": 0, "size": 4, "name": " Magic ", "kind": "ascii"}]})
        self.assertEqual(t["name"], "Header")
        self.assertEqual(t["description"], "")
        self.assertEqual(t["fields"], [field(0, 4, "Magic", "ascii")])

    def test_every_known_kind_can_be_used(self):
        sizes = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "i8": 1, "i16": 2,
                 "i32": 4, "i64": 8, "guid": 16}
        rows = [field(i * 16, sizes.get(k, 4), k, k)
                for i, k in enumerate(structure.TEMPLATE_KINDS)]
        t = structure.validate_template(tpl("All", *rows))
        got = structure.preview(t, bytes(range(256)) * 4, 0)
        self.assertEqual(got["skipped"], 0)
        self.assertEqual(len(got["fields"]), len(structure.TEMPLATE_KINDS))

    def test_names_are_required_and_bounded(self):
        self.bad(tpl(""), "name")
        self.bad(tpl("   "), "name")
        self.bad(tpl("x" * 81), "80")
        self.bad({"fields": tpl()["fields"]}, "name")
        self.bad(tpl("ok", field(0, 4, "", "u32")), "no name")
        self.bad(tpl("ok", field(0, 4, "x" * 81, "u32")), "80")

    def test_control_characters_and_non_text_are_refused(self):
        self.bad(tpl("a\nb"), "control")
        self.bad(tpl("a\x00b"), "control")
        self.bad(tpl("ok", field(0, 4, "n\x07", "u32")), "control")
        self.bad(tpl("ok", field(0, 4, "n", "u32", "x" * 201)), "200")
        self.bad({"name": 5, "fields": tpl()["fields"]}, "text")
        self.bad({"name": "n", "description": ["x"],
                  "fields": tpl()["fields"]}, "text")
        self.bad({"name": "n", "description": "x" * 501,
                  "fields": tpl()["fields"]}, "500")

    def test_fields_must_exist_and_be_bounded(self):
        self.bad({"name": "n", "fields": []}, "at least one")
        self.bad({"name": "n", "fields": "x"}, "at least one")
        self.bad({"name": "n"}, "at least one")
        self.bad(tpl("n", *[field(i, 1, "f", "u8") for i in range(513)]),
                 "512")
        self.bad(tpl("n", "notadict"), "object")
        self.bad("notadict", "object")

    def test_kind_offset_and_size_are_checked(self):
        self.bad(tpl("n", field(0, 4, "f", "float")), "kind")
        self.bad(tpl("n", field(0, 4, "f", None)), "kind")
        self.bad(tpl("n", field(0, 3, "f", "u32")), "4 bytes")
        self.bad(tpl("n", field(0, 8, "f", "guid")), "16 bytes")
        self.bad(tpl("n", field(0, 0, "f", "bytes")), "between 1")
        self.bad(tpl("n", field(0, 4097, "f", "bytes")), "4096")
        self.bad(tpl("n", field(-1, 4, "f", "u32")), "offset")
        self.bad(tpl("n", field(1 << 25, 4, "f", "u32")), "offset")
        self.bad(tpl("n", field(0, 33, "f", "hex")), "32")
        self.bad(tpl("n", field(65534, 4, "f", "u32")), "beyond")

    def test_only_whole_numbers_are_sizes_and_offsets(self):
        for v in (1.5, "4", True, None, [4]):
            self.bad(tpl("n", field(v, 4, "f", "u32")), "whole number")
            self.bad(tpl("n", field(0, v, "f", "u32")), "whole number")

    def test_overlapping_fields_are_allowed(self):
        structure.validate_template(tpl("n", field(0, 4, "a", "u32"),
                                        field(0, 2, "b", "u16")))


class Robust(unittest.TestCase):

    def test_arbitrary_input_is_refused_or_accepted_never_a_crash(self):
        import random
        rng = random.Random(7)
        atoms = [None, True, False, 0, 1, -1, 4, 16, 1 << 40, 1.5, "", "x",
                 "u32", "ascii", "guid", "\x00", "a" * 300, [], {}]

        def junk(depth=0):
            r = rng.random()
            if depth > 3 or r < 0.5:
                return rng.choice(atoms)
            if r < 0.75:
                return [junk(depth + 1) for _ in range(rng.randint(0, 4))]
            return {rng.choice(["name", "fields", "offset", "size", "kind",
                                "note", "description", "x"]): junk(depth + 1)
                    for _ in range(rng.randint(0, 5))}

        for _ in range(3000):
            try:
                structure.validate_template(junk())
            except ValueError:
                pass


class Preview(unittest.TestCase):

    def test_fields_are_decoded_and_offsets_are_in_the_image(self):
        t = structure.validate_template(tpl(
            "n", field(0, 4, "Magic", "ascii"), field(4, 2, "Ver", "u16"),
            field(6, 2, "Delta", "i16")))
        data = b"ABCD" + (258).to_bytes(2, "little") \
            + (-2).to_bytes(2, "little", signed=True)
        got = structure.preview(t, data, 1000)
        self.assertEqual([f["value"] for f in got["fields"]],
                         ["ABCD", 258, -2])
        self.assertEqual([f["offset"] for f in got["fields"]],
                         [1000, 1004, 1006])
        self.assertEqual(got["extent"], 8)

    def test_a_short_read_leaves_fields_out_and_says_how_many(self):
        t = structure.validate_template(tpl())
        got = structure.preview(t, b"ABCD\x01", 0)
        self.assertEqual([f["name"] for f in got["fields"]], ["Magic"])
        self.assertEqual(got["skipped"], 1)


class CaseStorage(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-tpl-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.path = os.path.join(self.dir, "c.strata")

    def open(self, who="Alice"):
        case = casedb.Case(self.path, examiner=who)
        self.addCleanup(case.close)
        return case

    def test_templates_persist_with_the_case_and_name_their_writer(self):
        a = self.open("Alice")
        saved = a.save_template(tpl())
        self.assertEqual((saved["name"], saved["revision"],
                          saved["examiner"]), ("Header", 1, "Alice"))
        a.close()
        b = self.open("Bob")
        got = b.templates()
        self.assertEqual([t["name"] for t in got], ["Header"])
        self.assertEqual(got[0]["fields"][0]["name"], "Magic")
        self.assertEqual(got[0]["examiner"], "Alice")

    def test_an_edit_bumps_the_revision_and_names_the_editor(self):
        a = self.open("Alice")
        t = a.save_template(tpl())
        b = self.open("Bob")
        edited = copy.deepcopy(tpl())
        edited["fields"][1]["name"] = "Major"
        t2 = b.save_template(edited, t["id"], t["revision"])
        self.assertEqual((t2["revision"], t2["examiner"]), (2, "Bob"))
        self.assertEqual(t2["fields"][1]["name"], "Major")
        self.assertEqual(t2["created_at"], t["created_at"])

    def test_an_edit_made_from_a_stale_read_is_refused(self):
        a = self.open("Alice")
        t = a.save_template(tpl())
        a.save_template(tpl("Header", field(0, 8, "Only", "u64")),
                        t["id"], t["revision"])
        # Bob still has revision 1 on screen.
        stale = a.save_template(tpl("Header", field(0, 1, "Mine", "u8")),
                                t["id"], t["revision"])
        self.assertIsNone(stale)
        self.assertEqual(a.template(t["id"])["fields"][0]["name"], "Only")

    def test_a_missing_template_cannot_be_edited(self):
        a = self.open()
        self.assertIsNone(a.save_template(tpl(), 999, 1))

    def test_names_are_unique_whatever_the_case(self):
        a = self.open()
        a.save_template(tpl("Header"))
        with self.assertRaises(ValueError):
            a.save_template(tpl("HEADER"))
        other = a.save_template(tpl("Other"))
        with self.assertRaises(ValueError):
            a.save_template(tpl("header"), other["id"], other["revision"])
        self.assertEqual(a.template(other["id"])["name"], "Other")
        # A template may keep its own name when it is saved again.
        again = a.save_template(tpl("Other"), other["id"], other["revision"])
        self.assertEqual(again["revision"], 2)

    def test_an_invalid_template_stores_nothing(self):
        a = self.open()
        with self.assertRaises(ValueError):
            a.save_template(tpl("n", field(0, 3, "f", "u32")))
        self.assertEqual(a.templates(), [])

    def test_delete_needs_the_current_revision_and_is_audited_whole(self):
        a = self.open("Alice")
        t = a.save_template(tpl())
        b = self.open("Bob")
        b.save_template(tpl("Header", field(0, 1, "x", "u8")),
                        t["id"], t["revision"])
        self.assertFalse(a.delete_template(t["id"], t["revision"]))
        self.assertEqual(len(a.templates()), 1)
        cur = a.template(t["id"])
        self.assertTrue(b.delete_template(cur["id"], cur["revision"]))
        self.assertEqual(a.templates(), [])
        kept = [e for e in a.audit() if e["action"] == "template.delete"]
        self.assertEqual(len(kept), 1)
        detail = json.loads(kept[0]["detail"]) \
            if isinstance(kept[0]["detail"], str) else kept[0]["detail"]
        self.assertEqual(detail["template"]["fields"][0]["name"], "x")
        self.assertEqual(kept[0]["examiner"], "Bob")

    def test_saves_are_in_the_audit_log(self):
        a = self.open()
        t = a.save_template(tpl())
        a.save_template(tpl(), t["id"], t["revision"])
        actions = [e["action"] for e in reversed(a.audit())
                   if e["action"].startswith("template.")]
        self.assertEqual(actions, ["template.add", "template.edit"])

    def test_a_damaged_row_is_listed_but_never_applied(self):
        a = self.open()
        t = a.save_template(tpl())
        a.db.execute("UPDATE structure_templates SET body=? WHERE id=?",
                     ('{"name": "Header", "fields": [{"kind": "zzz"}]}',
                      t["id"]))
        a.db.commit()
        got = a.templates()[0]
        self.assertEqual(got["fields"], [])
        self.assertIn("damaged", got)
        a.db.execute("UPDATE structure_templates SET body=? WHERE id=?",
                     ("not json", t["id"]))
        a.db.commit()
        self.assertIn("damaged", a.templates()[0])
        self.assertTrue(a.delete_template(t["id"], t["revision"]))
        gone = [e for e in a.audit() if e["action"] == "template.delete"][0]
        self.assertIn("not json", gone["detail"])

    def test_an_older_case_gains_the_table_when_opened(self):
        a = self.open()
        a.db.execute("DROP TABLE structure_templates")
        a.db.commit()
        a.close()
        b = self.open()
        self.assertEqual(b.templates(), [])
        b.save_template(tpl())
        self.assertEqual(len(b.templates()), 1)


class Api(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-tpl-api-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.c = Client()
        self.c.call("GET", "/")

    def new_case(self, name):
        status, _ = self.c.call("POST", "/api/case/new", {
            "path": os.path.join(self.dir, name), "name": name,
            "examiner": "Alice"})
        self.assertEqual(status, 200)
        return self.c.call("GET", "/api/case/templates")[1]["case"]

    def save(self, case, t=None, **kw):
        return self.c.call("POST", "/api/case/template",
                           dict({"case": case, "template": t or tpl()}, **kw))

    def test_templates_work_in_a_case_with_no_exhibit(self):
        case = self.new_case("a")
        status, r = self.c.call("GET", "/api/case/templates")
        self.assertEqual((status, r["templates"]), (200, []))
        self.assertIn("u32", r["kinds"])
        self.assertEqual(r["limits"]["fields"], structure.MAX_TEMPLATE_FIELDS)
        status, r = self.save(case)
        self.assertEqual(status, 200, r)
        self.assertEqual(r["template"]["revision"], 1)
        self.assertEqual([t["name"] for t in r["templates"]], ["Header"])

    def test_edit_and_delete_go_by_id_and_revision(self):
        case = self.new_case("a")
        _, r = self.save(case)
        tid, rev = r["id"], r["template"]["revision"]
        status, r = self.save(case, tpl("Renamed"), id=tid, revision=rev)
        self.assertEqual(status, 200, r)
        self.assertEqual(r["template"]["revision"], rev + 1)
        # The same edit again, from the old read, is a conflict.
        status, r = self.save(case, tpl("Stale"), id=tid, revision=rev)
        self.assertEqual(status, 409)
        self.assertEqual([t["name"] for t in r["templates"]], ["Renamed"])
        status, r = self.c.call("POST", "/api/case/template/delete",
                                {"case": case, "id": tid, "revision": rev})
        self.assertEqual(status, 409)
        status, r = self.c.call("POST", "/api/case/template/delete",
                                {"case": case, "id": tid, "revision": rev + 1})
        self.assertEqual((status, r["templates"]), (200, []))

    def test_bad_requests_are_refused_and_store_nothing(self):
        case = self.new_case("a")
        for kw in ({"template": {"name": "x", "fields": []}},
                   {"template": None}, {"template": "x"},
                   {"template": tpl("n", field(0, 3, "f", "u32"))}):
            status, r = self.c.call("POST", "/api/case/template",
                                    dict({"case": case}, **kw))
            self.assertEqual(status, 400, kw)
            self.assertIn("error", r)
        # An id without a revision, or the reverse, or ids that are not
        # whole numbers.
        for kw in ({"id": 1}, {"revision": 1}, {"id": "1", "revision": 1},
                   {"id": True, "revision": 1}, {"id": 1, "revision": 1.5}):
            status, _ = self.save(case, **kw)
            self.assertEqual(status, 400, kw)
        for kw in ({}, {"id": 1}, {"revision": 1}):
            status, _ = self.c.call("POST", "/api/case/template/delete",
                                    dict({"case": case}, **kw))
            self.assertEqual(status, 400, kw)
        self.assertEqual(self.c.call("GET", "/api/case/templates")[1]
                         ["templates"], [])

    def test_duplicate_names_are_a_400_with_the_reason(self):
        case = self.new_case("a")
        self.save(case)
        status, r = self.save(case, tpl("header"))
        self.assertEqual(status, 400)
        self.assertIn("already exists", r["error"])

    def test_a_page_showing_another_case_changes_nothing(self):
        a = self.new_case("a")
        _, r = self.save(a)
        b = self.new_case("b")
        status, r2 = self.save(a, tpl("Other"))
        self.assertEqual(status, 409)
        status, _ = self.save(None if False else "", tpl("Other"))
        self.assertEqual(status, 409)
        status, _ = self.c.call("POST", "/api/case/template/delete", {
            "case": a, "id": r["id"], "revision": 1})
        self.assertEqual(status, 409)
        self.assertEqual(self.c.call("GET", "/api/case/templates")[1]
                         ["templates"], [])
        self.assertNotEqual(a, b)

    def test_no_case_open_is_an_error(self):
        c = Client()
        c.call("GET", "/")
        self.assertEqual(c.call("GET", "/api/case/templates")[0], 400)
        self.assertEqual(c.call("POST", "/api/case/template",
                                {"template": tpl()})[0], 400)


class PreviewApi(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-tpl-prev-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.img = imagebuild_fat.build_fat(16)
        path = os.path.join(self.dir, "d.img")
        with open(path, "wb") as fh:
            fh.write(self.img)
        self.c = Client()
        self.c.call("GET", "/")
        status, r = self.c.call("POST", "/api/open", {
            "path": path, "case_path": os.path.join(self.dir, "c.strata"),
            "examiner": "Alice"})
        self.assertEqual(status, 200, r)

    def preview(self, **kw):
        return self.c.call("POST", "/api/structure/preview", kw)

    def test_a_template_is_applied_at_an_offset_without_being_saved(self):
        t = tpl("Boot", field(3, 8, "OEM", "ascii"),
                field(11, 2, "Bytes per sector", "u16"))
        status, r = self.preview(template=t, offset=0)
        self.assertEqual(status, 200, r)
        self.assertEqual(r["fields"][0]["value"], self.img[3:11]
                         .decode("ascii").rstrip())
        self.assertEqual(r["fields"][1]["value"],
                         int.from_bytes(self.img[11:13], "little"))
        self.assertEqual(r["fields"][1]["offset"], 11)
        self.assertEqual((r["skipped"], r["short"]), (0, False))
        _, listed = self.c.call("GET", "/api/case/templates")
        self.assertEqual(listed["templates"], [])

    def test_a_later_offset_and_a_partition_base(self):
        t = tpl("x", field(0, 2, "w", "u16"))
        _, r = self.preview(template=t, offset=510)
        self.assertEqual(r["fields"][0]["value"], 0xAA55)
        self.assertEqual(r["fields"][0]["offset"], 510)
        _, r = self.preview(template=t, offset=10, part=500)
        self.assertEqual(r["fields"][0]["offset"], 510)
        self.assertEqual(r["fields"][0]["value"], 0xAA55)

    def test_reading_past_the_end_leaves_fields_out_and_says_so(self):
        t = tpl("x", field(0, 2, "a", "u16"), field(100, 4, "b", "u32"))
        _, r = self.preview(template=t, offset=len(self.img) - 10)
        self.assertEqual([f["name"] for f in r["fields"]], ["a"])
        self.assertEqual((r["skipped"], r["short"]), (1, True))

    def test_bad_input_is_a_400(self):
        good = tpl("x", field(0, 2, "a", "u16"))
        for kw in ({"template": good, "offset": -1},
                   {"template": good, "offset": 1.5},
                   {"template": good, "offset": "0"},
                   {"template": good, "offset": True},
                   {"template": good},
                   {"template": good, "offset": 0, "part": -5},
                   {"template": good, "offset": len(self.img)},
                   {"template": good, "offset": 10 ** 12},
                   {"template": {"name": "x", "fields": []}, "offset": 0},
                   {"template": None, "offset": 0}):
            status, r = self.preview(**kw)
            self.assertEqual(status, 400, kw)
            self.assertIn("error", r)

    def test_a_preview_needs_evidence(self):
        c = Client()
        c.call("GET", "/")
        c.call("POST", "/api/case/new", {
            "path": os.path.join(self.dir, "n.strata"), "name": "n",
            "examiner": "A"})
        status, _ = c.call("POST", "/api/structure/preview", {
            "template": tpl(), "offset": 0})
        self.assertEqual(status, 409)


if __name__ == "__main__":
    unittest.main()
