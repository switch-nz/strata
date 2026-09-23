"""Unit tests for engine.fs.apfs's extended-attribute value parsing
(ApfsVolume._parse_xattr), against hand-built j_xattr_key_t/j_xattr_val_t
byte fragments -- there is no synthetic-image builder for APFS, so these
exercise the static parsing logic directly rather than a full volume."""

import struct
import unittest

from engine.fs.apfs import ApfsVolume


def xattr_key(name):
    name_bytes = name.encode("utf-8") + b"\x00"
    return b"\x00" * 8 + struct.pack("<H", len(name_bytes)) + name_bytes


def embedded_val(data):
    return struct.pack("<HH", ApfsVolume.XATTR_DATA_EMBEDDED, len(data)) + data


def stream_val(dstream_id=1):
    return struct.pack("<HH", ApfsVolume.XATTR_DATA_STREAM, 8) \
        + struct.pack("<Q", dstream_id)


class ParseXattr(unittest.TestCase):

    def test_embedded_value_is_returned_with_its_own_length(self):
        got = ApfsVolume._parse_xattr(
            xattr_key("com.apple.quarantine"), embedded_val(b"0083;5991b778;Safari"))
        self.assertEqual(got["name"], "com.apple.quarantine")
        self.assertEqual(got["size"], len(b"0083;5991b778;Safari"))
        self.assertEqual(got["value"], b"0083;5991b778;Safari")

    def test_stream_based_value_reports_size_but_no_captured_value(self):
        val = stream_val()
        got = ApfsVolume._parse_xattr(xattr_key("com.apple.ResourceFork"), val)
        self.assertEqual(got["name"], "com.apple.ResourceFork")
        self.assertNotIn("value", got)
        self.assertEqual(got["size"], len(val))

    def test_truncated_embedded_payload_falls_back_to_raw_length(self):
        # xdata_len claims 100 bytes but only 10 follow -- don't trust the
        # claimed length over what's actually there.
        val = struct.pack("<HH", ApfsVolume.XATTR_DATA_EMBEDDED, 100) + b"x" * 10
        got = ApfsVolume._parse_xattr(xattr_key("user.short"), val)
        self.assertNotIn("value", got)
        self.assertEqual(got["size"], len(val))

    def test_value_too_short_to_hold_flags_reports_raw_length_only(self):
        got = ApfsVolume._parse_xattr(xattr_key("user.tiny"), b"\x01\x02")
        self.assertEqual(got["size"], 2)
        self.assertNotIn("value", got)

    def test_key_too_short_to_hold_a_name_gives_an_empty_name(self):
        got = ApfsVolume._parse_xattr(b"\x00" * 8, embedded_val(b"data"))
        self.assertEqual(got["name"], "")

    def test_name_is_decoded_from_utf8_and_stops_at_the_null_terminator(self):
        key = xattr_key("com.apple.metadata:kMDItemWhereFroms")
        got = ApfsVolume._parse_xattr(key, embedded_val(b"bplist00"))
        self.assertEqual(got["name"], "com.apple.metadata:kMDItemWhereFroms")


if __name__ == "__main__":
    unittest.main()
