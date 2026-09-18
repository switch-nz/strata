"""Unit tests for the APFS reader (engine.fs.apfs), fed synthetic
container images from imagebuild_apfs, including snapshot listing and
read-only snapshot volume access."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_apfs as build                               # noqa: E402
from engine.ewf import OffsetReader                           # noqa: E402
from engine.fs import apfs                                    # noqa: E402
from engine.fs.ntfs import open_fs                            # noqa: E402


class MemImage(object):
    """The read_at/size surface an image object offers, over bytes."""

    bytes_per_sector = 512

    def __init__(self, data):
        self.data = data
        self.size = len(data)

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + length]


def mount(data):
    """Open a filesystem the way the server does: OffsetReader -> open_fs."""
    img = MemImage(data)
    return open_fs(OffsetReader(img, 0, img.size))


class ApfsFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fs = mount(build.build_apfs())

    def by_name(self, fs, name):
        entries = {e["name"]: e for e in fs.listdir(2, "/")}
        return entries[name]


class Detection(ApfsFixture):
    def test_open_fs_detects_apfs(self):
        self.assertIsInstance(self.fs, apfs.ApfsVolume)
        self.assertEqual(self.fs.name, "APFS")

    def test_info_reports_volume_fields(self):
        info = self.fs.info()
        self.assertEqual(info["type"], "APFS")
        self.assertEqual(info["label"], build.LABEL.decode())
        self.assertEqual(info["uuid"], build.UUID.hex())
        self.assertFalse(info["encrypted"])

    def test_live_volume_lists_file(self):
        entries = self.fs.listdir(2, "/")
        self.assertEqual([e["name"] for e in entries], ["live.txt"])
        self.assertEqual(self.fs.read_file(entries[0]), build.LIVE_TXT)


class Snapshots(ApfsFixture):
    def test_snapshots_lists_one(self):
        snaps = self.fs.snapshots()
        self.assertEqual(len(snaps), 1)
        snap = snaps[0]
        self.assertEqual(snap["name"], build.SNAP_NAME)
        self.assertEqual(snap["xid"], build.SNAP_XID)
        self.assertEqual(snap["created_at"], "2023-11-14T22:13:20Z")
        self.assertEqual(snap["inum"], 3)
        self.assertFalse(snap["dataless"])

    def test_snapshot_volume_reads_old_contents(self):
        sv = self.fs.snapshot_volume(build.SNAP_NAME)
        self.assertEqual(sv.snap_name, build.SNAP_NAME)
        entries = sv.listdir(2, "/")
        self.assertEqual([e["name"] for e in entries], ["old.txt"])
        entry = entries[0]
        self.assertEqual(sv.read_file(entry), build.OLD_TXT)
        self.assertEqual(sv.read_range(entry, 1, 2), b"ld")
        self.assertEqual(sv.stat(entry)["object_id"], 3)
        self.assertEqual(sv.stat(entry)["mode"], "0o100644")

    def test_unknown_snapshot_name_raises(self):
        self.assertRaises(ValueError, self.fs.snapshot_volume, "nope")


class NoSnapshots(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fs = mount(build.build_apfs_no_snapshots())

    def test_snapshots_empty(self):
        self.assertEqual(self.fs.snapshots(), [])

    def test_live_volume_still_reads(self):
        entries = self.fs.listdir(2, "/")
        self.assertEqual([e["name"] for e in entries], ["live.txt"])
        self.assertEqual(self.fs.read_file(entries[0]), build.LIVE_TXT)


class DatalessSnapshot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fs = mount(build.build_apfs_dataless())

    def test_snapshots_flags_dataless(self):
        snaps = self.fs.snapshots()
        self.assertEqual(len(snaps), 1)
        self.assertTrue(snaps[0]["dataless"])

    def test_snapshot_volume_rejects_dataless(self):
        with self.assertRaises(ValueError) as ctx:
            self.fs.snapshot_volume(build.SNAP_NAME)
        self.assertIn("dataless", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()