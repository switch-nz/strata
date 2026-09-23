"""Unit tests for engine.bitlocker, fed a synthetic FVE volume from
imagebuild_bitlocker. There was no prior test file for this module at all,
so this covers both the pre-existing password/recovery-password unlock
paths (regression) and the new clear-key and startup-key (.BEK) paths."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_bitlocker as build                              # noqa: E402
from engine import bitlocker                                      # noqa: E402


class MemImage:
    def __init__(self, data):
        self.data = data
        self.size = len(data)

    def read_at(self, offset, length):
        if offset < 0:
            return b""
        return self.data[offset:offset + length]


class ProtectorTypes(unittest.TestCase):
    """The numeric protector-type values, verified against the libyal/libbde
    format spec and cross-checked against bitlocker2john.c -- TPM and
    Startup key sit in the high byte (0x0100/0x0200), not 0x0001/0x0002."""

    def test_startup_key_is_0x0200_not_0x0002(self):
        name, kind, _ = bitlocker.PROTECTOR_TYPES[0x0200]
        self.assertEqual((name, kind), ("Startup key", "keyfile"))
        self.assertNotIn(0x0002, bitlocker.PROTECTOR_TYPES)

    def test_tpm_is_0x0100_not_0x0001(self):
        name, kind, _ = bitlocker.PROTECTOR_TYPES[0x0100]
        self.assertEqual((name, kind), ("TPM", "tpm"))
        self.assertNotIn(0x0001, bitlocker.PROTECTOR_TYPES)

    def test_clear_key_recovery_and_password_unchanged(self):
        self.assertEqual(bitlocker.PROTECTOR_TYPES[0x0000][1], "none")
        self.assertEqual(bitlocker.PROTECTOR_TYPES[0x0800][1], "recovery")
        self.assertEqual(bitlocker.PROTECTOR_TYPES[0x2000][1], "password")

    def test_an_unrecognised_type_value_falls_back_cleanly(self):
        p = bitlocker.Protector(__import__("uuid").uuid4(), None, 0x0300, [])
        self.assertEqual(p.kind, "unknown")
        self.assertFalse(p.usable)
        self.assertIn("0x0300", p.name)


class ParseBekFile(unittest.TestCase):

    def test_well_formed_file_yields_the_raw_key(self):
        key_id = __import__("uuid").uuid4()
        raw = b"\x55" * 32
        data = build.build_bek_file(key_id, raw)
        self.assertEqual(bitlocker.parse_bek_file(data), raw)

    def test_too_short_to_hold_a_header_returns_none(self):
        self.assertIsNone(bitlocker.parse_bek_file(b"\x00" * 10))

    def test_garbage_after_a_valid_header_returns_none(self):
        header = build.build_bek_file(__import__("uuid").uuid4(), b"\x00" * 32)[:48]
        self.assertIsNone(bitlocker.parse_bek_file(header + b"not an entry"))


class SyntheticVolume(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image, cls.bek_file = build.build_bitlocker_volume()
        cls.image_no_clear, _ = build.build_bitlocker_volume(include_clear=False)

    def vault(self, image=None):
        return bitlocker.BitLocker(MemImage(image if image is not None
                                            else self.image),
                                   size=len(image if image is not None
                                            else self.image))

    def test_looks_like_bitlocker_detects_the_signature(self):
        self.assertTrue(bitlocker.looks_like_bitlocker(self.image[:16]))
        self.assertFalse(bitlocker.looks_like_bitlocker(b"\x00" * 16))

    def test_all_four_protectors_are_recognised_and_usable(self):
        v = self.vault()
        by_kind = {p.kind: p for p in v.protectors}
        self.assertEqual(set(by_kind), {"none", "keyfile", "recovery", "password"})
        self.assertTrue(all(p.usable for p in v.protectors))

    def test_info_reports_every_usable_kind_as_accepted(self):
        info = self.vault().info()
        self.assertTrue(info["recoverable"])
        self.assertEqual(set(info["accepts"]),
                         {"none", "keyfile", "recovery", "password"})
        self.assertEqual(info["encryption"], "AES-XTS 256")


class Unlock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image, cls.bek_file = build.build_bitlocker_volume()
        cls.image_no_clear, _ = build.build_bitlocker_volume(include_clear=False)

    def vault(self, image=None):
        image = self.image if image is None else image
        return bitlocker.BitLocker(MemImage(image), size=len(image))

    def test_clear_key_unlocks_with_no_secret_at_all(self):
        r = self.vault().unlock("")
        self.assertTrue(r["unlocked"])
        self.assertEqual(r["protector"], "Clear key")
        self.assertTrue(r["verified"])
        self.assertEqual(r["verified_filesystem"], "NTFS")

    def test_startup_key_unlocks_with_the_matching_bek_file(self):
        bek_key = bitlocker.parse_bek_file(self.bek_file)
        r = self.vault().unlock("", bek_key=bek_key, kind="keyfile")
        self.assertTrue(r["unlocked"])
        self.assertEqual(r["protector"], "Startup key")
        self.assertTrue(r["verified"])

    def test_startup_key_rejects_the_wrong_key_file(self):
        r = self.vault().unlock("", bek_key=b"\x00" * 32, kind="keyfile")
        self.assertFalse(r["unlocked"])

    def test_startup_key_without_a_bek_file_finds_nothing_to_try(self):
        r = self.vault().unlock("", kind="keyfile")
        self.assertFalse(r["unlocked"])

    def test_recovery_password_unlocks(self):
        r = self.vault().unlock(build.RECOVERY_KEY, kind="recovery")
        self.assertTrue(r["unlocked"])
        self.assertEqual(r["protector"], "Recovery password")
        self.assertTrue(r["verified"])

    def test_password_unlocks(self):
        r = self.vault().unlock(build.PASSWORD, kind="password")
        self.assertTrue(r["unlocked"])
        self.assertEqual(r["protector"], "Password")
        self.assertTrue(r["verified"])

    def test_wrong_password_is_rejected_without_a_clear_key_present(self):
        r = self.vault(self.image_no_clear).unlock("not the password")
        self.assertFalse(r["unlocked"])
        self.assertIn("Incorrect", r["reason"])

    def test_right_password_still_unlocks_without_a_clear_key_present(self):
        r = self.vault(self.image_no_clear).unlock(build.PASSWORD)
        self.assertTrue(r["unlocked"])

    def test_empty_secret_without_a_clear_key_or_bek_asks_for_one(self):
        r = self.vault(self.image_no_clear).unlock("")
        self.assertFalse(r["unlocked"])
        self.assertEqual(r["reason"], "No password or key supplied.")

    def test_a_recovery_key_typed_into_the_password_field_is_not_confused(self):
        # _is_recovery_format's own shape check should route a 48-digit
        # string to the recovery protector, not fail as a wrong password.
        # No clear key here, or it would win regardless of what routing
        # happened underneath it.
        r = self.vault(self.image_no_clear).unlock(build.RECOVERY_KEY)
        self.assertTrue(r["unlocked"])
        self.assertEqual(r["protector"], "Recovery password")


if __name__ == "__main__":
    unittest.main()
