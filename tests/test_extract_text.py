"""What the text extractor keeps (engine.textindex.extract_text).

Every pair of bytes decodes as some UTF-16 character, so the extractor has
to find real UTF-16 text -- in any script, starting on any byte -- without
also keeping the plausible-looking characters that binary data, and text
read one byte out of step, decode to.
"""

import os
import random
import re
import sys
import unicodedata
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.textindex import extract_text                        # noqa: E402

REAL = {
    "Chinese": "文件已被删除，请联系管理员恢复数据",
    "Chinese, another": "我们明天在会议室讨论这个项目的预算",
    "Japanese": "ファイルを削除できませんでした。もう一度お試しください",
    "Korean": "파일을 삭제할 수 없습니다 다시 시도하십시오",
    "Russian": "Невозможно удалить файл. Повторите попытку",
    "Ukrainian": "Видалення файлу неможливе",
    "Greek": "Δεν ήταν δυνατή η διαγραφή του αρχείου",
    "Arabic": "تعذر حذف الملف يرجى المحاولة مرة أخرى",
    "Hebrew": "לא ניתן למחוק את הקובץ נסה שוב",
    "Hindi": "फ़ाइल हटाई नहीं जा सकी कृपया पुनः प्रयास करें",
    "Thai": "ไม่สามารถลบไฟล์ได้ โปรดลองอีกครั้ง",
    "French": "Le fichier a été supprimé à cause d'une erreur",
    "Vietnamese": "Không thể xóa tệp này vì lỗi",
    "English": "The file could not be deleted",
}


def words(s):
    return [w for w in re.split(r"[\s，。.、]+", s) if len(w) >= 2]


def noise(rnd, n):
    return bytes(rnd.randrange(256) for _ in range(n))


def extract(data):
    return extract_text(data, limit=1 << 22)


class RealText(unittest.TestCase):

    def test_utf16_text_in_every_script_at_even_and_odd_offsets(self):
        rnd = random.Random(1)
        for lang, s in REAL.items():
            for trial in range(12):
                # Random binary right up against the text on both sides.
                data = (noise(rnd, 64 + trial) + s.encode("utf-16-le")
                        + noise(rnd, 128))
                got = extract(data)
                for w in words(s):
                    self.assertIn(w, got, "%s, trial %d" % (lang, trial))

    def test_a_short_katakana_word(self):
        data = b"\x01\x02\x03" + "ファイル".encode("utf-16-le") + b"\x00\x00"
        self.assertIn("ファイル", extract(data))

    def test_utf8_and_ascii_text_is_kept_as_before(self):
        data = b"\x00\x01plain ascii text here\xff\xfe"
        self.assertIn("plain ascii text here", extract(data))


class AsciiStoredAsUtf16(unittest.TestCase):

    def test_at_an_odd_offset(self):
        data = b"\x07" + "ColourName=blue".encode("utf-16-le") + b"\x00\x00"
        self.assertIn("ColourName=blue", extract(data))

    def test_digits_inside_other_scripts_text(self):
        s = "Код ошибки: 0x8004FEED/0x8004BEEF Повторите"
        got = extract(s.encode("utf-16-le"))
        self.assertIn("0x8004FEED/0x8004BEEF", got)
        self.assertIn("Повторите", got)

    def test_numbers_beside_binary(self):
        # A value table with single-byte separators that knock the rest out
        # of step: the digits must survive whatever they are next to.
        data = ("KEY=".encode("utf-16-le")[1:] + b"\t"
                + "1357".encode("utf-16-le") + b"\t"
                + "2468".encode("utf-16-le") + b"\x00\x00")
        got = extract(data)
        self.assertIn("1357", got)
        self.assertIn("2468", got)


class Noise(unittest.TestCase):

    def non_ascii(self, text):
        return sum(1 for ch in text if ord(ch) >= 0x80)

    def test_random_binary_yields_far_less_non_ascii(self):
        rnd = random.Random(2)
        data = noise(rnd, 1 << 18)
        got = extract(data)
        # Keeping every printable run kept about 100,000 characters from
        # this. What still gets through is ideographs and Hangul only:
        # telling a random run of them from real text would take knowing
        # which characters are common, which this does not try.
        self.assertLess(self.non_ascii(got), 40000)
        east_asian = ("CJK", "HANGUL", "HIRAGANA", "KATAKANA", "HALFWIDTH",
                      "BOPOMOFO", "IDEOGRAPHIC")
        leaked = [ch for ch in got if ord(ch) >= 0x80
                  and unicodedata.category(ch)[0] == "L"
                  and not unicodedata.name(ch, "").startswith(east_asian)]
        self.assertEqual(leaked, [])

    def test_utf16_english_read_out_of_step_is_not_kept_as_ideographs(self):
        s = "The quick brown fox jumps over the lazy dog. " * 50
        data = b"\x01" + s.encode("utf-16-le")
        got = extract(data)
        self.assertIn("The quick brown fox", got)
        self.assertEqual(self.non_ascii(got), 0)

    def test_ascii_read_as_utf16_is_not_kept(self):
        s = ("Window resize handler returns value " * 40).encode("ascii")
        got = extract(s)
        self.assertEqual(self.non_ascii(got), 0)

    def test_repeated_binary_is_not_kept(self):
        data = bytes([0x11, 0xCC, 0x52, 0xCC, 0x93, 0xCC, 0xA4, 0xCC]) * 64
        self.assertEqual(self.non_ascii(extract(data)), 0)


class Modes(unittest.TestCase):

    def test_ascii_only_keeps_no_other_script(self):
        data = (REAL["Russian"].encode("utf-16-le") + b"\x00\x00"
                + "wide ascii".encode("utf-16-le"))
        got = extract_text(data, limit=1 << 20, wide_ascii_only=True)
        self.assertIn("wide ascii", got)
        self.assertEqual(sum(1 for ch in got if ord(ch) >= 0x80), 0)

    def test_limit(self):
        data = b"word " * 10000 + REAL["Greek"].encode("utf-16-le")
        self.assertEqual(len(extract_text(data, limit=100)), 100)

    def test_min_run(self):
        data = "abc".encode("utf-16-le") + b"\x00\x00xyz\x00"
        self.assertEqual(extract_text(data, limit=100), "")
        self.assertEqual(extract_text(data, limit=100, min_run=3),
                         "xyz abc")


if __name__ == "__main__":
    unittest.main()
