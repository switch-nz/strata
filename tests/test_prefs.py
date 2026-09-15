"""Unit tests for the preferences whitelist (engine.prefs.clean)."""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import prefs                                          # noqa: E402


class CleanStringRules(unittest.TestCase):
    """String-tuple rules: keep known values, drop everything else."""

    def test_theme_accepts_all_whitelisted_values(self):
        for theme in ("dark", "light", "midnight", "sepia", "contrast",
                      "paper"):
            self.assertEqual(prefs.clean({"theme": theme}),
                             {"theme": theme})

    def test_theme_rejects_unknown_value(self):
        self.assertEqual(prefs.clean({"theme": "bogus"}), {})

    def test_theme_rejects_non_string(self):
        for bad in (123, True, None, ["light"], {"theme": "light"}):
            self.assertEqual(prefs.clean({"theme": bad}), {})

    def test_other_string_rules_behave_the_same(self):
        self.assertEqual(prefs.clean({"folder_view": "gallery"}),
                         {"folder_view": "gallery"})
        self.assertEqual(prefs.clean({"folder_view": "grid"}), {})
        self.assertEqual(prefs.clean({"time_display": "utc"}),
                         {"time_display": "utc"})
        self.assertEqual(prefs.clean({"offset_mode": "sideways"}), {})

    def test_unknown_keys_are_ignored_not_stored(self):
        self.assertEqual(prefs.clean({"not_a_pref": "value"}), {})


class CleanNumericRules(unittest.TestCase):
    """Integer-range rules: clamped, non-numeric dropped, bool rejected."""

    def test_within_range_kept(self):
        self.assertEqual(prefs.clean({"tree_width": 320}),
                         {"tree_width": 320})

    def test_clamped_at_both_bounds(self):
        self.assertEqual(prefs.clean({"tree_width": 1}),
                         {"tree_width": 160})
        self.assertEqual(prefs.clean({"tree_width": 10_000}),
                         {"tree_width": 640})

    def test_floats_accepted_and_truncated(self):
        self.assertEqual(prefs.clean({"tree_width": 320.7}),
                         {"tree_width": 320})

    def test_non_numeric_dropped(self):
        for bad in ("320", True, None, [320]):
            self.assertEqual(prefs.clean({"tree_width": bad}), {})

    def test_bool_rule_coerces_anything(self):
        self.assertEqual(prefs.clean({"split_hex": "yes"}),
                         {"split_hex": True})
        self.assertEqual(prefs.clean({"split_hex": 0}),
                         {"split_hex": False})


class CleanDictRules(unittest.TestCase):
    """None-rule keys accept dicts only; notice channels are filtered."""

    def test_dict_kept_non_dict_dropped(self):
        cols = {"tree": ["name", "size"]}
        self.assertEqual(prefs.clean({"columns": cols}), {"columns": cols})
        self.assertEqual(prefs.clean({"columns": ["nope"]}), {})

    def test_open_sections_same_rule(self):
        self.assertEqual(prefs.clean({"open_sections": {"a": True}}),
                         {"open_sections": {"a": True}})
        self.assertEqual(prefs.clean({"open_sections": 7}), {})

    def test_notice_channels_filter_unknown_and_coerce(self):
        out = prefs.clean({"notify": {"action": 1, "task": 0,
                                      "colleague": "yes", "evil": True}})
        self.assertEqual(out, {"notify": {"action": True, "task": False,
                                          "colleague": True}})


class CleanCarveRules(unittest.TestCase):
    """carve-types filters extension-shaped strings; signatures validate."""

    def test_carve_types_filter_and_cap(self):
        self.assertEqual(
            prefs.clean({"carve_types_off": ["exe", "BAD!", "jpg"]}),
            {"carve_types_off": ["exe", "jpg"]})
        many = ["a%s" % i for i in range(150)]
        self.assertEqual(len(prefs.clean({"carve_types_off": many})
                             ["carve_types_off"]), 100)

    def test_carve_types_non_list_dropped(self):
        self.assertEqual(prefs.clean({"carve_types_off": "exe"}), {})

    def test_valid_signature_kept_with_canonical_fields(self):
        spec = {"id": "sig_pk", "ext": "pk", "name": "PKzip",
                "header": "50 4B 03 04"}
        out = prefs.clean({"carve_signatures": [spec]})
        sig = out["carve_signatures"][0]
        self.assertEqual(sig["id"], "sig_pk")
        self.assertEqual(sig["ext"], "pk")
        self.assertEqual(sig["header"], "50 4B 03 04")

    def test_invalid_specs_dropped_without_raising(self):
        good = {"id": "sig_pk", "ext": "pk", "name": "PKzip",
                "header": "50 4B 03 04"}
        bad_ext = dict(good, ext="not an ext!")
        bad_id = dict(good, id="bad id!")
        out = prefs.clean({"carve_signatures": [bad_ext, bad_id, 5, "junk"]})
        self.assertEqual(out, {"carve_signatures": []})

    def test_duplicate_ids_kept_once(self):
        spec = {"id": "sig_pk", "ext": "pk", "name": "PKzip",
                "header": "50 4B 03 04"}
        out = prefs.clean({"carve_signatures": [spec, dict(spec)]})
        self.assertEqual(len(out["carve_signatures"]), 1)


class CleanLanguageRule(unittest.TestCase):
    def test_installed_language_kept_unknown_dropped(self):
        with mock.patch.object(prefs, "installed_languages",
                               lambda: ["en-GB", "de-DE"]):
            self.assertEqual(prefs.clean({"language": "de-DE"}),
                             {"language": "de-DE"})
            self.assertEqual(prefs.clean({"language": "xx-YY"}), {})


class PutRoundTrip(unittest.TestCase):
    """put() stores cleaned values per examiner and forget() clears them."""

    def setUp(self):
        self._config = tempfile.mkdtemp(prefix="strata-prefs-test-")
        self._patch = mock.patch.dict(os.environ,
                                      {"STRATA_CONFIG_DIR": self._config})
        self._patch.start()
        self.addCleanup(self._patch.stop)
        self.addCleanup(lambda: shutil.rmtree(self._config, ignore_errors=True))

    def test_put_get_forget_round_trip(self):
        stored = prefs.put("roundtrip", {"theme": "midnight", "bogus": 1})
        self.assertEqual(stored.get("theme"), "midnight")
        self.assertEqual(prefs.get("roundtrip").get("theme"), "midnight")
        self.assertNotIn("bogus", stored)
        prefs.forget("roundtrip")
        self.assertEqual(prefs.get("roundtrip"), {})


if __name__ == "__main__":
    unittest.main()