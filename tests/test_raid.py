"""Unit tests for RAID 0, 1 and 5 sets (engine.raid): every definition is
checked before anything is read, the placement of chunks follows the four md
layouts, a RAID 5 set missing a member is rebuilt by XOR and says so, and
what the members hold that should agree is reported as observed."""

import hashlib
import os
import random
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import raid                                          # noqa: E402
import imagebuild_raid as build                                  # noqa: E402
import imagebuild_fat                                            # noqa: E402

C = 4096


def payload(n, seed=1):
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


# The md documentation's diagrams: the data chunk on each member, row by row
# (P is parity), for four members.
TABLES = {
    "left-symmetric": [["D0", "D1", "D2", "P"], ["D4", "D5", "P", "D3"],
                       ["D8", "P", "D6", "D7"], ["P", "D9", "D10", "D11"]],
    "left-asymmetric": [["D0", "D1", "D2", "P"], ["D3", "D4", "P", "D5"],
                        ["D6", "P", "D7", "D8"], ["P", "D9", "D10", "D11"]],
    "right-symmetric": [["P", "D0", "D1", "D2"], ["D5", "P", "D3", "D4"],
                        ["D7", "D8", "P", "D6"], ["D9", "D10", "D11", "P"]],
    "right-asymmetric": [["P", "D0", "D1", "D2"], ["D3", "P", "D4", "D5"],
                         ["D6", "D7", "P", "D8"], ["D9", "D10", "D11", "P"]],
}


class Placement(unittest.TestCase):

    def test_each_layout_places_chunks_as_the_md_diagrams_do(self):
        for layout, table in TABLES.items():
            for row, want in enumerate(table):
                got = [None] * 4
                got[raid.parity_disk(layout, row, 4)] = "P"
                for k in range(3):
                    got[raid.data_disk(layout, row, k, 4)] = "D%d" % (
                        row * 3 + k)
                self.assertEqual(got, want, (layout, row))

    def test_the_test_builder_agrees_with_the_diagrams_too(self):
        for layout, table in TABLES.items():
            for row, want in enumerate(table):
                pd, order = build.parity_and_data(layout, row, 4)
                got = [None] * 4
                got[pd] = "P"
                for k, disk in enumerate(order):
                    got[disk] = "D%d" % (row * 3 + k)
                self.assertEqual(got, want, (layout, row))

    def test_parity_never_lands_on_a_data_member_for_other_sizes(self):
        for layout in raid.LAYOUTS:
            for n in (3, 5, 8):
                for row in range(2 * n):
                    disks = {raid.data_disk(layout, row, k, n)
                             for k in range(n - 1)}
                    self.assertEqual(len(disks), n - 1)
                    self.assertNotIn(raid.parity_disk(layout, row, n), disks)


class Definition(unittest.TestCase):

    def members(self, n, **kw):
        return [dict({"path": "/x/m%d.img" % i, "offset": 0}, **kw)
                for i in range(n)]

    def good(self, **kw):
        d = {"name": "Set", "level": 5, "chunk": 65536,
             "members": self.members(3)}
        d.update(kw)
        return d

    def bad(self, d, text):
        with self.assertRaises(ValueError) as cm:
            raid.clean_definition(d)
        self.assertIn(text, str(cm.exception), d)

    def test_a_good_definition_is_normalised(self):
        d = raid.clean_definition(self.good(name="  Set "))
        self.assertEqual((d["name"], d["level"], d["chunk"], d["layout"]),
                         ("Set", 5, 65536, "left-symmetric"))
        self.assertIsNone(d["primary"])
        self.assertEqual(d["members"][0], {"path": "/x/m0.img", "offset": 0})

    def test_levels_chunks_and_layouts_are_checked(self):
        for level in (2, 6, 10, "5", None, True, 5.0 + 0.5):
            self.bad(self.good(level=level), "level")
        for chunk in (None, 0, 100, 4097, 511, 1 << 27, "64k", 1.5, True):
            self.bad(self.good(chunk=chunk), "chunk")
        self.bad(self.good(layout="backwards"), "layout")
        # A mirror has no chunk or layout, and ignores what it is given.
        d = raid.clean_definition(self.good(level=1, chunk="junk",
                                            layout="x"))
        self.assertEqual((d["chunk"], d["layout"]), (None, None))

    def test_names_and_member_lists_are_checked(self):
        for name in (None, "", "   ", 5):
            self.bad(self.good(name=name), "name")
        self.bad(self.good(name="x" * 81), "80")
        self.bad(self.good(name="a\nb"), "control")
        self.bad("x", "object")
        self.bad(self.good(members=None), "members")
        self.bad(self.good(members=["x"] * 3), "object")
        self.bad(self.good(level=5, members=self.members(2)), "at least 3")
        self.bad(self.good(level=0, members=self.members(1)), "at least 2")
        self.bad(self.good(members=self.members(33)), "at most 32")

    def test_offsets_and_paths_are_checked(self):
        for off in (-1, 1.5, "0", True, 1 << 51):
            m = self.members(3)
            m[1]["offset"] = off
            self.bad(self.good(members=m), "offset")
        m = self.members(3)
        m[1]["path"] = 5
        self.bad(self.good(members=m), "path")
        m[1]["path"] = "a\x00b"
        self.bad(self.good(members=m), "path")
        m = self.members(3)
        m[2]["path"] = m[0]["path"]
        self.bad(self.good(members=m), "same file")

    def test_missing_members_are_allowed_only_where_they_can_be_read(self):
        m = self.members(3)
        m[1]["path"] = None
        raid.clean_definition(self.good(members=m))
        m[2]["path"] = ""
        self.bad(self.good(members=m), "not two")
        m = self.members(3)
        m[0]["path"] = None
        self.bad(self.good(level=0, members=m), "RAID 0")
        m = self.members(2)
        m[1]["path"] = None
        d = raid.clean_definition(self.good(level=1, members=m))
        self.assertEqual(d["primary"], 0)
        m[0]["path"] = None
        self.bad(self.good(level=1, members=m), "At least one")

    def test_a_mirror_is_read_from_a_present_member(self):
        m = self.members(3)
        m[0]["path"] = None
        d = raid.clean_definition(self.good(level=1, members=m))
        self.assertEqual(d["primary"], 1)
        self.bad(self.good(level=1, members=m, primary=0), "present")
        self.bad(self.good(level=1, members=m, primary=7), "present")
        self.bad(self.good(level=1, members=m, primary="1"), "whole number")

    def test_the_identifier_follows_the_definition(self):
        a = raid.clean_definition(self.good())
        b = raid.clean_definition(self.good())
        c = raid.clean_definition(self.good(chunk=131072))
        self.assertEqual(raid.set_id(a), raid.set_id(b))
        self.assertNotEqual(raid.set_id(a), raid.set_id(c))
        self.assertTrue(raid.is_set_id(raid.set_id(a)))
        self.assertFalse(raid.is_set_id("/some/disk.img"))
        self.assertFalse(raid.is_set_id("strata-raid-x/y"))
        odd = raid.clean_definition(self.good(name="../../etc/passwd"))
        self.assertTrue(raid.is_set_id(raid.set_id(odd)))


class Sets(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-raid-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))

    def write(self, blobs, missing=()):
        paths = []
        for i, b in enumerate(blobs):
            p = os.path.join(self.dir, "member%d.img" % i)
            with open(p, "wb") as fh:
                fh.write(b)
            paths.append(None if i in missing else p)
        return paths

    def open(self, virtual, level, n, chunk=None, layout=None, offset=0,
             missing=(), **kw):
        blobs = build.split(virtual, level, n, chunk,
                            layout or "left-symmetric", offset)
        paths = self.write(blobs, missing)
        d = {"name": "T", "level": level, "chunk": chunk, "layout": layout,
             "members": [{"path": p, "offset": offset} for p in paths]}
        d.update(kw)
        img = raid.RaidImage(d)
        self.addCleanup(img.close)
        return img

    def assertReads(self, img, virtual, trials=200, seed=3):
        rng = random.Random(seed)
        self.assertEqual(img.read_at(0, img.size), virtual[:img.size])
        for _ in range(trials):
            off = rng.randrange(0, img.size)
            n = rng.choice([1, 7, 511, 512, 4095, 4096, 4097, 20000, 70000])
            self.assertEqual(img.read_at(off, n), virtual[off:off + n],
                             (off, n))


class Raid0(Sets):

    def test_reads_stripes_across_members(self):
        v = payload(8 * C * 3)
        img = self.open(v, 0, 3, C)
        self.assertEqual(img.size, len(v))
        self.assertReads(img, v)
        self.assertEqual(img.info()["findings"], [])

    def test_a_data_offset_on_each_member_is_skipped(self):
        v = payload(4 * C * 2)
        img = self.open(v, 0, 2, C, offset=8192)
        self.assertReads(img, v)

    def test_an_array_size_is_whole_chunks_of_the_smallest_member(self):
        v = payload(4 * C * 2)
        blobs = build.split(v, 0, 2, C)
        blobs[1] = blobs[1][:-100]        # a member a little short
        paths = self.write(blobs)
        img = raid.RaidImage({"name": "T", "level": 0, "chunk": C,
                              "members": [{"path": p} for p in paths]})
        self.addCleanup(img.close)
        self.assertEqual(img.size, 2 * 3 * C)
        self.assertEqual(img.read_at(0, img.size), v[:img.size])
        text = " ".join(img.info()["findings"])
        self.assertIn("not the same size", text)
        self.assertIn("less than a whole chunk", text)

    def test_reads_past_the_end_are_empty_and_short_at_the_end(self):
        v = payload(4 * C * 2)
        img = self.open(v, 0, 2, C)
        self.assertEqual(img.read_at(img.size, 10), b"")
        self.assertEqual(img.read_at(-1, 10), b"")
        self.assertEqual(img.read_at(0, 0), b"")
        self.assertEqual(len(img.read_at(img.size - 3, 100)), 3)

    def test_a_member_that_ends_early_reads_as_zeros_and_says_so(self):
        v = payload(4 * C * 2)
        img = self.open(v, 0, 2, C)
        # Shrink a member after the geometry was worked out.
        path = img.segment_paths[1]
        with open(path, "r+b") as fh:
            fh.truncate(2 * C)
        img2 = raid.RaidImage(img.definition)
        self.addCleanup(img2.close)
        self.assertEqual(img2.size, 2 * (2 * C))
        # The other member is longer than the array uses, so this is the
        # unequal-size case, not a short read: force the short read.
        img2._per += 2 * C
        img2.size += 4 * C
        got = img2.read_at(img2.size - 10, 10)
        self.assertEqual(got, bytes(10))
        self.assertTrue(any("ended before" in f for f in img2.findings))

    def test_a_member_that_is_not_there_is_named(self):
        v = payload(4 * C * 2)
        img = self.open(v, 0, 2, C)
        d = dict(img.definition)
        d["members"] = [dict(m) for m in d["members"]]
        d["members"][1]["path"] = os.path.join(self.dir, "gone.img")
        with self.assertRaises(raid.RaidError) as cm:
            raid.RaidImage(d)
        self.assertIn("gone.img", str(cm.exception))
        self.assertIn("Member 2", str(cm.exception))

    def test_a_member_smaller_than_its_offset_is_refused(self):
        v = payload(4 * C * 2)
        paths = self.write(build.split(v, 0, 2, C))
        with self.assertRaises(raid.RaidError):
            raid.RaidImage({"name": "T", "level": 0, "chunk": C, "members": [
                {"path": paths[0]}, {"path": paths[1], "offset": 1 << 30}]})

    def test_a_set_smaller_than_one_chunk_is_refused(self):
        paths = self.write([b"x" * 100, b"y" * 100])
        with self.assertRaises(raid.RaidError):
            raid.RaidImage({"name": "T", "level": 0, "chunk": C,
                            "members": [{"path": p} for p in paths]})

    def test_there_is_nothing_to_compare_in_a_stripe_set(self):
        img = self.open(payload(4 * C * 2), 0, 2, C)
        r = img.check_consistency()
        self.assertIsNone(r["kind"])
        self.assertIn("no redundancy", r["summary"])


class Raid1(Sets):

    def test_reads_the_primary_member(self):
        v = payload(10 * C)
        img = self.open(v, 1, 2)
        self.assertEqual(img.size, len(v))
        self.assertReads(img, v)

    def test_reads_from_the_chosen_member_even_when_mirrors_differ(self):
        v = payload(4 * C)
        blobs = build.split(v, 1, 2)
        other = bytearray(blobs[1])
        other[100] ^= 0xFF
        blobs[1] = bytes(other)
        paths = self.write(blobs)
        for primary, want in ((0, v), (1, bytes(other))):
            img = raid.RaidImage({"name": "T", "level": 1, "primary": primary,
                                  "members": [{"path": p} for p in paths]})
            self.addCleanup(img.close)
            self.assertEqual(img.read_at(0, img.size), want)
            self.assertIn("member %d" % (primary + 1),
                          img.info()["acquisition"]["read from"])

    def test_identical_mirrors_are_reported_identical(self):
        img = self.open(payload(6 * C), 1, 3)
        r = img.check_consistency()
        self.assertEqual((r["kind"], r["differing_ranges"]), ("mirror", 0))
        self.assertIn("identical", r["summary"])
        self.assertEqual(r["members_compared"], 3)

    def test_mirrors_that_differ_are_reported_as_observed(self):
        v = payload(8 * C)
        blobs = build.split(v, 1, 3)
        a, b = bytearray(blobs[1]), bytearray(blobs[2])
        a[1000] ^= 1                    # one sector of member 2
        a[1300] ^= 1                    # the next sector
        b[5 * C + 10] ^= 1              # a sector of member 3 elsewhere
        b[1000] ^= 1                    # and member 3 shares the first one
        paths = self.write([blobs[0], bytes(a), bytes(b)])
        img = raid.RaidImage({"name": "T", "level": 1,
                              "members": [{"path": p} for p in paths]})
        self.addCleanup(img.close)
        r = img.check_consistency()
        self.assertEqual(r["differing_members"], [2, 3])
        self.assertEqual(r["ranges"], [{"start": 512, "end": 1536},
                                       {"start": 5 * C, "end": 5 * C + 512}])
        self.assertEqual(r["differing_bytes"], 1024 + 512)
        self.assertIn("does not say which is right", r["summary"])
        self.assertIn(r["summary"], img.info()["findings"])

    def test_a_mirror_with_a_member_missing_reads_and_says_so(self):
        v = payload(4 * C)
        img = self.open(v, 1, 2, missing=(0,))
        self.assertReads(img, v, trials=20)
        self.assertEqual(img.definition["primary"], 1)
        self.assertTrue(any("missing" in f for f in img.info()["findings"]))
        self.assertIsNone(img.check_consistency()["kind"])


class Raid5(Sets):

    def test_every_layout_and_member_count_reads_back(self):
        for layout in raid.LAYOUTS:
            for n in (3, 4, 5):
                v = payload(C * (n - 1) * 5 + 1234, seed=n)
                img = self.open(v, 5, n, C, layout)
                row = C * (n - 1)
                self.assertEqual(img.size, -(-len(v) // row) * row)
                self.assertReads(img, v + bytes(img.size - len(v)),
                                 trials=40, seed=n)

    def test_the_default_layout_is_left_symmetric(self):
        v = payload(C * 2 * 4)
        blobs = build.split(v, 5, 3, C, "left-symmetric")
        paths = self.write(blobs)
        img = raid.RaidImage({"name": "T", "level": 5, "chunk": C,
                              "members": [{"path": p} for p in paths]})
        self.addCleanup(img.close)
        self.assertEqual(img.layout, "left-symmetric")
        self.assertEqual(img.read_at(0, len(v)), v)

    def test_the_wrong_layout_does_not_read_back(self):
        v = payload(C * 2 * 4)
        paths = self.write(build.split(v, 5, 3, C, "left-symmetric"))
        img = raid.RaidImage({"name": "T", "level": 5, "chunk": C,
                              "layout": "right-asymmetric",
                              "members": [{"path": p} for p in paths]})
        self.addCleanup(img.close)
        self.assertNotEqual(img.read_at(0, len(v)), v)

    def test_a_data_offset_on_each_member_is_skipped(self):
        v = payload(C * 2 * 4)
        img = self.open(v, 5, 3, C, offset=4096)
        self.assertReads(img, v, trials=30)

    def test_a_consistent_set_matches_parity_everywhere(self):
        img = self.open(payload(C * 3 * 4), 5, 4, C)
        r = img.check_consistency()
        self.assertEqual((r["kind"], r["rows_inconsistent"]), ("parity", 0))
        self.assertEqual(r["rows_checked"], 4)
        self.assertIn("match", r["summary"])

    def test_parity_that_does_not_match_is_reported_as_observed(self):
        v = payload(C * 2 * 6)
        blobs = build.split(v, 5, 3, C)
        bad = bytearray(blobs[0])
        bad[2 * C + 5] ^= 0x40          # a byte in row 2 of member 1
        bad[4 * C + 5] ^= 0x40          # and one in row 4
        paths = self.write([bytes(bad), blobs[1], blobs[2]])
        img = raid.RaidImage({"name": "T", "level": 5, "chunk": C,
                              "members": [{"path": p} for p in paths]})
        self.addCleanup(img.close)
        r = img.check_consistency()
        self.assertEqual((r["rows_checked"], r["rows_inconsistent"]), (6, 2))
        span = 2 * C
        self.assertEqual(r["ranges"], [{"start": 2 * span, "end": 3 * span},
                                       {"start": 4 * span, "end": 5 * span}])
        self.assertIn("not how the set was built", r["summary"])

    def test_each_member_missing_in_turn_is_rebuilt_exactly(self):
        for layout in raid.LAYOUTS:
            v = payload(C * 3 * 5, seed=9)
            for gone in range(4):
                img = self.open(v, 5, 4, C, layout, missing=(gone,))
                self.assertReads(img, v, trials=25, seed=gone)
                text = " ".join(img.info()["findings"])
                self.assertIn("Member %d is missing" % (gone + 1), text)
                self.assertIn("rebuilt by XOR", text)

    def test_only_data_on_the_missing_member_counts_as_rebuilt(self):
        v = payload(C * 2 * 6)
        img = self.open(v, 5, 3, C, missing=(1,))
        img.read_at(0, len(v))
        got = img.info()["acquisition"]["bytes rebuilt from parity so far"]
        # One of the three members' chunks in every row is not parity; with a
        # member missing, half of each row's two data chunks... count it.
        rows = len(v) // (2 * C)
        parity_on_missing = sum(
            1 for r in range(rows)
            if raid.parity_disk("left-symmetric", r, 3) == 1)
        self.assertEqual(got, (rows - parity_on_missing) * C)

    def test_a_degraded_set_has_nothing_to_check_against_parity(self):
        img = self.open(payload(C * 2 * 4), 5, 3, C, missing=(0,))
        r = img.check_consistency()
        self.assertIsNone(r["kind"])
        self.assertIn("no redundancy", r["summary"])

    def test_two_members_missing_is_refused(self):
        v = payload(C * 2 * 4)
        paths = self.write(build.split(v, 5, 3, C), missing=(0, 1))
        with self.assertRaises(ValueError):
            raid.RaidImage({"name": "T", "level": 5, "chunk": C,
                            "members": [{"path": p} for p in paths]})


class Surface(Sets):

    def test_verify_hashes_the_array_and_reports_what_it_compared(self):
        v = payload(C * 2 * 4)
        img = self.open(v, 5, 3, C)
        seen = []
        got = img.verify(progress=seen.append)
        whole = img.read_at(0, img.size)
        self.assertEqual(got["computed_sha1"], hashlib.sha1(whole).hexdigest())
        self.assertEqual(got["computed_md5"], hashlib.md5(whole).hexdigest())
        self.assertIsNone(got["stored_sha1"])
        self.assertIn("no acquisition hash", got["note"])
        self.assertIn("parity", got["note"].lower())
        self.assertEqual(got["raid"]["kind"], "parity")
        self.assertTrue(seen and seen == sorted(seen) and seen[-1] <= 1.0)

    def test_info_names_the_set_its_members_and_the_files_it_reads(self):
        img = self.open(payload(C * 2 * 4), 5, 3, C, "right-symmetric",
                        offset=512)
        info = img.info()
        self.assertEqual(info["format"],
                         "RAID 5 (3 members, 4.0 KiB chunk, right-symmetric)")
        self.assertTrue(info["raid"])
        self.assertEqual(info["size"], img.size)
        acq = info["acquisition"]
        self.assertEqual((acq["level"], acq["members present"]), ("RAID 5", 3))
        self.assertIn("data starts at 512", acq["member 1"])
        self.assertEqual(img.parent_paths(), img.segment_paths)
        self.assertEqual(info["segments"], ["T"])
        self.assertEqual(info["sector_count"], img.size // 512)
        self.assertEqual(img.path, raid.set_id(img.definition))
        self.assertEqual(img.stamp_path, img.segment_paths[0])

    def test_the_seek_and_read_interface(self):
        v = payload(C * 2 * 4)
        img = self.open(v, 0, 2, C)
        img.seek(100)
        self.assertEqual(img.read(50), v[100:150])
        img.seek(-10, 2)
        self.assertEqual(img.read(), v[-10:])

    def test_close_closes_every_member_even_when_opening_one_failed(self):
        closed = []

        class Member:
            size = 8 * C

            def __init__(self, path):
                self.path = path

            def read_at(self, off, n):
                return bytes(n)

            def close(self):
                closed.append(self.path)

        paths = self.write([b"x" * (8 * C)] * 3)
        d = {"name": "T", "level": 0, "chunk": C,
             "members": [{"path": p} for p in paths]}
        img = raid.RaidImage(d, opener=Member)
        img.close()
        self.assertEqual(sorted(closed), sorted(paths))
        self.assertEqual(img._members, [])
        closed.clear()

        def flaky(path):
            if path == paths[2]:
                raise OSError("no")
            return Member(path)

        with self.assertRaises(raid.RaidError):
            raid.RaidImage(d, opener=flaky)
        self.assertEqual(sorted(closed), sorted(paths[:2]))

    def test_a_filesystem_inside_a_set_is_found_and_read(self):
        from engine import ewf, volume
        fat = imagebuild_fat.build_fat(16)
        for level, n, layout in ((0, 2, None), (1, 2, None),
                                 (5, 4, "left-asymmetric")):
            img = self.open(fat, level, n, 65536 if level != 1 else None,
                            layout)
            self.assertEqual(img.read_at(0, len(fat)), fat)
            scan = volume.scan(img)
            self.assertTrue(any(p.get("detected") for p in scan["partitions"]),
                            (level, scan))


if __name__ == "__main__":
    unittest.main()
