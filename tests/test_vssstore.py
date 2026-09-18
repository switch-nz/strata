"""Unit tests for engine.vssstore.SnapshotReader.

Stores are built as raw bytes the way libvshadow's format description lays
them out: each store is a chain of 0x4000-byte blocks; block 0 holds a 128
-byte header (VSS GUID, version 1, record type 3) followed by 32-byte block
descriptors ({orig, rel, sdb, flags, bitmap}); the store's data lives
wherever the descriptors point. The reader layers the chain of stores
newest-first over the live volume.
"""

import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from engine import vssstore
from engine.vss import VSS_GUID

BLOCK = 0x4000
SUB = 512
FWD, OVR, IGN = 0x01, 0x02, 0x04


def guid_bytes():
    # VSS GUID little-endian encoding as libvshadow writes it.
    import uuid
    return uuid.UUID(VSS_GUID).bytes_le


def store_block(descriptors, next_off=0):
    """One 0x4000 block: 128B header + descriptors. descriptors = list of
    (orig, rel, sdb, flags, bitmap) tuples."""
    b = bytearray(BLOCK)
    b[0:16] = guid_bytes()
    struct.pack_into("<II", b, 16, 1, 3)          # version, record type
    struct.pack_into("<Q", b, 40, next_off)       # next block offset
    for i, d in enumerate(descriptors):
        struct.pack_into("<QQQII", b, 128 + i * 32, *d)
    return bytes(b)


class FakeVolume:
    """Pattern-filled volume: byte at offset o = (o * 7 % 251)."""

    def __init__(self, size):
        self.size = size
        self.bytes_per_sector = 512
        self.data = bytes([(o * 7) % 251 for o in range(size)])

    def read_at(self, offset, length):
        return self.data[offset:offset + length]


def build_store(vol, store_off, descriptors, next_off=0):
    """Place a store block at store_off in the volume image and, for every
    descriptor, a 0x4000 data block at its sdb (unless flags & IGN)."""
    vol.data = vol.data[:store_off] + store_block(descriptors, next_off) \
        + vol.data[store_off + BLOCK:]
    for orig, rel, sdb, flags, bitmap in descriptors:
        if flags & IGN:
            continue
        if flags & OVR:
            # bitmap says which 512B sub-blocks carry store bytes; store
            # the set bits' pattern at sdb + i*SUB
            for i in range(BLOCK // SUB):
                if bitmap >> i & 1:
                    d = bytes([(store_off + sdb + i * SUB) % 251]) * SUB
                    off = sdb + i * SUB
                    vol.data = vol.data[:off] + d + vol.data[off + SUB:]
        else:
            d = bytes([sdb % 251]) * BLOCK
            vol.data = vol.data[:sdb] + d + vol.data[sdb + BLOCK:]
    return store_off


class DescriptorPath(unittest.TestCase):

    def setUp(self):
        self.vol = FakeVolume(0x100000)

    def test_descriptor_hit_serves_store_bytes(self):
        store = 0x10000
        sdb = 0x20000
        build_store(self.vol, store, [(0x0, 0, sdb, 0, 0)])
        r = vssstore.SnapshotReader(self.vol, [store])
        data = r.read_at(0, BLOCK)
        self.assertEqual(data, (sdb % 251).to_bytes(1, "little") * BLOCK)
        self.assertEqual(r.findings, [])

    def test_miss_falls_through_to_live_volume(self):
        store = 0x10000
        build_store(self.vol, store, [(0x40000, 0, 0x60000, 0, 0)])
        r = vssstore.SnapshotReader(self.vol, [store])
        self.assertEqual(r.read_at(0, BLOCK), self.vol.data[0:BLOCK])

    def test_two_store_chain_newest_wins(self):
        old, new = 0x10000, 0x18000
        sdb_old, sdb_new = 0x20000, 0x28000
        # Old store: blocks 0 and 0x4000; new store: block 0 only.
        build_store(self.vol, old, [(0, 0, sdb_old, 0, 0),
                                    (BLOCK, 0, sdb_old + BLOCK, 0, 0)])
        build_store(self.vol, new, [(0, 0, sdb_new, 0, 0)])
        r = vssstore.SnapshotReader(self.vol, [new, old])
        self.assertEqual(r.read_at(0, BLOCK),
                         (sdb_new % 251).to_bytes(1, "little") * BLOCK)
        self.assertEqual(r.read_at(BLOCK, BLOCK),
                         ((sdb_old + BLOCK) % 251).to_bytes(1, "little")
                         * BLOCK)

    def test_overlay_bitmap_mixes_store_and_volume(self):
        store = 0x10000
        sdb = 0x20000
        # sub-blocks 0 and 2 stored, the rest fall through.
        build_store(self.vol, store, [(0, 0, sdb, OVR, 0b101)])
        r = vssstore.SnapshotReader(self.vol, [store])
        got = r.read_at(0, BLOCK)
        stored = bytes([(store + sdb) % 251]) * SUB
        self.assertEqual(got[0:SUB], stored)
        self.assertEqual(got[2 * SUB:3 * SUB],
                         bytes([(store + sdb + 2 * SUB) % 251]) * SUB)
        # Sub-block 1 comes from the live volume: exactly the bytes the
        # FakeVolume holds at its own offset 512.
        self.assertEqual(got[SUB:2 * SUB],
                         self.vol.data[SUB:2 * SUB])

    def test_ignored_descriptor_is_skipped(self):
        store = 0x10000
        sdb = 0x20000
        build_store(self.vol, store, [(0, 0, sdb, IGN, 0)])
        r = vssstore.SnapshotReader(self.vol, [store])
        self.assertEqual(r.read_at(0, BLOCK), self.vol.data[0:BLOCK])

    def test_malformed_header_layer_is_skipped(self):
        self.vol.data = self.vol.data[:0x10000] + b"\x00" * 64 \
            + self.vol.data[0x10000 + 64:]
        r = vssstore.SnapshotReader(self.vol, [0x10000])
        self.assertEqual(r.read_at(0, BLOCK), self.vol.data[0:BLOCK])
        self.assertTrue(any("block list" in f for f in r.findings))

    def test_forwarder_reads_through_next_store(self):
        old, new = 0x10000, 0x18000
        sdb_old, sdb_new = 0x20000, 0x28000
        # Old store: block 0 lives at sdb_old.
        build_store(self.vol, old, [(0, 0, sdb_old, 0, 0)])
        # New store: block 0 is forwarded; rel = old store's block 0 entry.
        build_store(self.vol, new, [(rel := 0, old, 0, FWD, 0)],
                    next_off=old)
        r = vssstore.SnapshotReader(self.vol, [new, old])
        self.assertEqual(r.read_at(0, BLOCK),
                         (sdb_old % 251).to_bytes(1, "little") * BLOCK)

    def test_size_passthrough(self):
        r = vssstore.SnapshotReader(self.vol, [])
        self.assertEqual(r.size, self.vol.size)
        self.assertEqual(r.bytes_per_sector, 512)

    def test_read_seek_stream_helpers(self):
        r = vssstore.SnapshotReader(self.vol, [])
        r.seek(10)
        self.assertEqual(len(r.read(16)), 16)
        self.assertEqual(r._pos, 26)


class OpenFsIntegration(unittest.TestCase):
    """Booting NtfsFS off a SnapshotReader: reads inside the store come
    from the store; reads outside come from the live volume bytes."""

    def test_open_fs_boots_off_reader(self):
        import imagebuild_ntfs
        from test_fs_fat import ImageFiles, open_first_volume
        from engine.fs import ntfs

        img = imagebuild_ntfs.build_ntfs()
        files = ImageFiles()
        try:
            image = files.open(img)
            layout, part, fs = open_first_volume(image)
            # Collect some live bytes the boot sector region of the
            # partition; the reader wraps an OffsetReader over the same
            # partition, so an empty store list must behave identically.
            src = image
            from engine.ewf import OffsetReader
            off = part["offset"]
            r = vssstore.SnapshotReader(OffsetReader(
                image, part["offset"], part["size"], part["slot"]), [])
            live = ntfs.open_fs(r)
            self.assertEqual(live.name, "NTFS")
            boot_live = r.read_at(0, 512)
            self.assertEqual(len(boot_live), 512)
        finally:
            files.close()


if __name__ == "__main__":
    unittest.main()