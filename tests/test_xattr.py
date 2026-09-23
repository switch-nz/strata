import base64
import datetime
import plistlib
import unittest

from engine import xattr

_CF_EPOCH = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)


class DecodeQuarantine(unittest.TestCase):

    def test_well_formed_value_decodes_all_four_fields(self):
        value = b"0083;5991b778;Safari;A1B2C3D4-0000-0000-0000-000000000000"
        got = xattr.decode_quarantine(value)
        self.assertEqual(got["flags"], "0x0083")
        self.assertEqual(got["agent"], "Safari")
        expected = (_CF_EPOCH + datetime.timedelta(seconds=int("5991b778", 16))).isoformat()
        self.assertEqual(got["downloaded_at"], expected)
        self.assertEqual(got["event_id"], "A1B2C3D4-0000-0000-0000-000000000000")

    def test_missing_event_id_is_left_out_not_guessed(self):
        got = xattr.decode_quarantine(b"0083;5991b778;Chrome")
        self.assertNotIn("event_id", got)

    def test_empty_agent_field_is_reported_as_none(self):
        got = xattr.decode_quarantine(b"0083;5991b778;")
        self.assertIsNone(got["agent"])

    def test_too_few_fields_is_not_a_quarantine_value(self):
        self.assertIsNone(xattr.decode_quarantine(b"0083;5991b778"))

    def test_non_hex_flags_is_not_a_quarantine_value(self):
        self.assertIsNone(xattr.decode_quarantine(b"zz;5991b778;Safari"))

    def test_non_hex_timestamp_reports_downloaded_at_as_none(self):
        got = xattr.decode_quarantine(b"0083;not-a-timestamp;Safari")
        self.assertIsNone(got["downloaded_at"])

    def test_non_ascii_bytes_are_not_a_quarantine_value(self):
        self.assertIsNone(xattr.decode_quarantine(b"\xff\xfe\x00\x01"))

    def test_timestamp_uses_core_foundation_epoch_not_hfs_epoch(self):
        # Second 0 of CF absolute time is 2001-01-01 UTC, not HFS+'s 1904 epoch.
        got = xattr.decode_quarantine(b"0000;0;Safari")
        self.assertEqual(got["downloaded_at"], "2001-01-01T00:00:00+00:00")


class DecodeWherefroms(unittest.TestCase):

    def test_binary_plist_array_of_strings_decodes(self):
        urls = ["https://example.com/file.dmg", "https://example.com/"]
        blob = plistlib.dumps(urls, fmt=plistlib.FMT_BINARY)
        self.assertEqual(xattr.decode_wherefroms(blob), urls)

    def test_xml_plist_array_of_strings_also_decodes(self):
        urls = ["https://example.com/file.dmg"]
        blob = plistlib.dumps(urls, fmt=plistlib.FMT_XML)
        self.assertEqual(xattr.decode_wherefroms(blob), urls)

    def test_empty_array_is_not_returned(self):
        blob = plistlib.dumps([], fmt=plistlib.FMT_BINARY)
        self.assertIsNone(xattr.decode_wherefroms(blob))

    def test_array_of_non_strings_is_not_returned(self):
        blob = plistlib.dumps([1, 2, 3], fmt=plistlib.FMT_BINARY)
        self.assertIsNone(xattr.decode_wherefroms(blob))

    def test_non_array_plist_is_not_returned(self):
        blob = plistlib.dumps({"url": "https://example.com"}, fmt=plistlib.FMT_BINARY)
        self.assertIsNone(xattr.decode_wherefroms(blob))

    def test_garbage_bytes_are_not_a_plist(self):
        self.assertIsNone(xattr.decode_wherefroms(b"not a plist"))


class Decode(unittest.TestCase):

    def test_unrecognised_attribute_name_decodes_to_none(self):
        self.assertIsNone(xattr.decode("com.apple.ResourceFork", b"anything"))

    def test_none_value_decodes_to_none(self):
        self.assertIsNone(xattr.decode(xattr.QUARANTINE, None))


class ForClient(unittest.TestCase):

    def test_captured_value_is_base64_encoded(self):
        out = xattr.for_client([{"name": "user.other", "size": 3, "value": b"abc"}])
        self.assertEqual(out[0]["value"], base64.b64encode(b"abc").decode("ascii"))
        self.assertNotIn("decoded", out[0])

    def test_recognised_attribute_gets_a_decoded_field_alongside_value(self):
        raw = b"0083;5991b778;Safari"
        out = xattr.for_client([{"name": xattr.QUARANTINE, "size": len(raw), "value": raw}])
        self.assertIn("value", out[0])
        self.assertEqual(out[0]["decoded"]["agent"], "Safari")

    def test_entry_with_no_captured_value_keeps_only_name_and_size(self):
        out = xattr.for_client([{"name": "com.apple.ResourceFork", "size": 4096}])
        self.assertEqual(out[0], {"name": "com.apple.ResourceFork", "size": 4096})
        self.assertNotIn("value", out[0])
        self.assertNotIn("decoded", out[0])

    def test_empty_or_missing_list_returns_empty_list(self):
        self.assertEqual(xattr.for_client([]), [])
        self.assertEqual(xattr.for_client(None), [])


if __name__ == "__main__":
    unittest.main()
