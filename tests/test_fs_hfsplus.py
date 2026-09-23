"""Unit tests for engine.fs.hfsplus's Attributes B-tree leaf-record parsing
(HfsPlus._attr_record), against hand-built HFSPlusAttrKey/attribute-record
byte fragments -- there is no synthetic-image builder for HFS+, so these
exercise the static parsing logic directly on a small node-sized buffer
rather than a full B-tree."""

import struct
import unittest

from engine.fs.hfsplus import ATTR_FORK_DATA, ATTR_INLINE_DATA, HfsPlus


def attr_key(file_id, name, start_block=0):
    name_u16 = name.encode("utf-16-be")
    name_len = len(name)
    body = struct.pack(">HII", 0, file_id, start_block) \
        + struct.pack(">H", name_len) + name_u16
    key_length = len(body)
    return struct.pack(">H", key_length) + body


def inline_record(value):
    return struct.pack(">III", ATTR_INLINE_DATA, 0, len(value)) + value


def build_node(key_off, key, data_off, record, total_len=None):
    node = bytearray(total_len or (data_off + len(record) + 16))
    node[key_off:key_off + len(key)] = key
    node[data_off:data_off + len(record)] = record
    return bytes(node)


class AttrRecord(unittest.TestCase):

    def test_inline_data_record_decodes_name_size_and_value(self):
        value = b"0083;5991b778;Safari"
        key = attr_key(42, "com.apple.quarantine")
        key_off = 20
        data_off = key_off + 2 + (len(key) - 2)
        data_off += data_off & 1
        node = build_node(key_off, key, data_off, inline_record(value))

        got = HfsPlus._attr_record(node, key_off, data_off)

        self.assertIsNotNone(got)
        file_id, rec = got
        self.assertEqual(file_id, 42)
        self.assertEqual(rec["name"], "com.apple.quarantine")
        self.assertEqual(rec["size"], len(value))
        self.assertEqual(rec["value"], value)

    def test_fork_data_record_reports_name_but_no_size_or_value(self):
        key = attr_key(7, "com.apple.ResourceFork")
        key_off = 0
        data_off = key_off + 2 + (len(key) - 2)
        data_off += data_off & 1
        record = struct.pack(">III", ATTR_FORK_DATA, 0, 0) + b"\x00" * 60
        node = build_node(key_off, key, data_off, record)

        file_id, rec = HfsPlus._attr_record(node, key_off, data_off)

        self.assertEqual(file_id, 7)
        self.assertEqual(rec["name"], "com.apple.ResourceFork")
        self.assertIsNone(rec["size"])
        self.assertNotIn("value", rec)

    def test_value_truncated_by_node_boundary_keeps_size_but_drops_value(self):
        key = attr_key(1, "user.short")
        key_off = 0
        data_off = key_off + 2 + (len(key) - 2)
        data_off += data_off & 1
        full_value = b"the rest of this never arrives"
        record = struct.pack(">III", ATTR_INLINE_DATA, 0, len(full_value)) \
            + full_value[:5]
        node = build_node(key_off, key, data_off, record)

        file_id, rec = HfsPlus._attr_record(node, key_off, data_off)

        self.assertEqual(rec["size"], len(full_value))
        self.assertNotIn("value", rec)

    def test_key_that_does_not_fit_in_the_node_returns_none(self):
        node = bytes(10)
        self.assertIsNone(HfsPlus._attr_record(node, key_off=5, data_off=20))

    def test_record_header_past_the_node_boundary_reports_size_none(self):
        key = attr_key(3, "user.x")
        key_off = 0
        data_off = key_off + 2 + (len(key) - 2)
        data_off += data_off & 1
        node = bytearray(data_off + 2)
        node[key_off:key_off + len(key)] = key
        file_id, rec = HfsPlus._attr_record(bytes(node), key_off, data_off)
        self.assertEqual(file_id, 3)
        self.assertEqual(rec["name"], "user.x")
        self.assertIsNone(rec["size"])


if __name__ == "__main__":
    unittest.main()
