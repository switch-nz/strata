"""Tests for engine.browsercache: Chromium Simple Cache and Firefox
cache2 entry parsing, classification of walked entries, and collect()
over a fake filesystem tree. All byte fixtures are built in code; the
repo carries no binary test fixtures."""

import struct
import unittest

from engine import browsercache as bc


def simple_entry(url=b"https://example.com/page",
                 headers=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
                 stream1=b"BODY", with_sha=False, magic=None):
    """Build Chromium Simple Cache `_0` bytes."""
    key = url
    magic = bc.SIMPLE_INITIAL_MAGIC if magic is None else magic
    sha = bytes(range(32)) if with_sha else b""
    flags0 = 1 | (2 if with_sha else 0)
    return (bc._SIMPLE_HDR.pack(magic, 3, len(key), 0, 0)
            + key + stream1
            + bc._SIMPLE_EOF.pack(bc.SIMPLE_FINAL_MAGIC, 1, 0, 0, 0)
            + headers
            + sha
            + bc._SIMPLE_EOF.pack(bc.SIMPLE_FINAL_MAGIC, flags0,
                                  0, len(headers), 0))


def cache2_entry(key=b":https://example.com/page", version=3,
                 fetched=1700000000, modified=1690000000,
                 elements=b"response-head\0HTTP/1.1 200 OK\r\n"
                           b"Content-Type: text/css\r\n\r\n\0"):
    """Build Firefox cache2 entry bytes: body + metadata + metaOffset."""
    body = b"X" * 300
    hash_count = -(-len(body) // bc.CHUNK_SIZE)
    fields = [version, 7, fetched, modified, 100, 999999999, len(key)]
    if version >= 2:
        fields.append(0)  # flags
        header = struct.pack(">%dI" % len(fields), *fields)
    else:
        header = struct.pack(">7I", *fields)
    metadata = (struct.pack(">I", 0x12345678)          # metadata hash
                + b"\x00\x00" * hash_count             # chunk hashes
                + header
                + key + b"\0"
                + elements)
    return body + metadata + struct.pack(">I", len(body))


class ParseSimple(unittest.TestCase):

    def test_row_carries_url_status_and_content_type(self):
        r = bc.parse_simple_entry(simple_entry())
        self.assertEqual(r["url"], "https://example.com/page")
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["content_type"], "text/html")
        self.assertEqual(r["source"], "chromium")
        self.assertEqual(r["key"], "https://example.com/page")
        self.assertIsNone(r["last_modified"])
        self.assertIsNone(r["last_fetched"])
        self.assertIsNone(r["fetched_count"])
        self.assertIsNone(r["note"])

    def test_key_sha256_variant_parses_identically(self):
        r = bc.parse_simple_entry(simple_entry(with_sha=True))
        self.assertEqual(r["url"], "https://example.com/page")
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["content_type"], "text/html")
        self.assertIsNone(r["note"])

    def test_wrong_initial_magic_is_rejected(self):
        self.assertIsNone(bc.parse_simple_entry(simple_entry(magic=0x1234)))

    def test_stream0_size_beyond_the_head_is_rejected(self):
        data = simple_entry()
        # Rewrite the trailing EOF's stream0_size to something impossible.
        bad = (data[:-24]
               + bc._SIMPLE_EOF.pack(bc.SIMPLE_FINAL_MAGIC, 1, 0, 10 ** 6, 0))
        self.assertIsNone(bc.parse_simple_entry(bad))

    def test_missing_http_head_gives_a_row_with_a_note(self):
        key = b"https://example.com/page"
        data = (bc._SIMPLE_HDR.pack(bc.SIMPLE_INITIAL_MAGIC, 3, len(key), 0, 0)
                + key + b"B"
                + bc._SIMPLE_EOF.pack(bc.SIMPLE_FINAL_MAGIC, 1, 0, 0, 0)
                + b"garbage without a header"
                + bc._SIMPLE_EOF.pack(bc.SIMPLE_FINAL_MAGIC, 1, 0, 0, 0))
        r = bc.parse_simple_entry(data)
        self.assertEqual(r["url"], "https://example.com/page")
        self.assertIsNone(r["status"])
        self.assertIn("no HTTP headers", r["note"])


class StatusLine(unittest.TestCase):

    def test_an_http_slash_inside_a_header_is_not_the_status_line(self):
        head = (b"HTTP/1.0 404 Not Found\r\n"
                b"Server: BaseHTTP/0.6 Python/3\r\n"
                b"Content-Type: text/plain\r\n\r\n")
        r = bc.parse_simple_entry(simple_entry(headers=head))
        self.assertEqual(r["status"], 404)
        self.assertEqual(r["content_type"], "text/plain")

    def test_http2_status_line_without_a_reason_phrase(self):
        r = bc.parse_simple_entry(simple_entry(
            headers=b"HTTP/1.1 304\r\nContent-Type: text/css\r\n\r\n"))
        self.assertEqual(r["status"], 304)


class ChromiumKeys(unittest.TestCase):
    """Chromium HTTP cache keys are ``credential_key/upload_id/
    [isolation_key]url`` (net/http/http_cache.cc), and a partitioned
    cache's isolation key starts ``_dk_`` and ends at the last space. The
    numeric ids of the service worker script cache are not URLs at all. The
    row's URL comes from the key that way, and its `key` is the raw key."""

    def row(self, key):
        return bc.parse_simple_entry(simple_entry(url=key))

    def test_a_partitioned_cache_key_gives_the_resource_url(self):
        key = (b"1/0/_dk_https://top.example https://frame.example "
               b"https://res.example/img/a.png?x=1")
        r = self.row(key)
        self.assertEqual(r["url"], "https://res.example/img/a.png?x=1")
        self.assertEqual(r["key"], key.decode())
        self.assertEqual(r["status"], 200)

    def test_a_single_keyed_entry_gives_the_url_after_the_prefix(self):
        r = self.row(b"1/0/https://res.example/b.css")
        self.assertEqual(r["url"], "https://res.example/b.css")

    def test_a_post_upload_id_is_skipped(self):
        r = self.row(b"1/1234567/https://res.example/post")
        self.assertEqual(r["url"], "https://res.example/post")

    def test_a_bare_url_key_from_an_older_cache_is_used_as_it_is(self):
        r = self.row(b"https://old.example/x")
        self.assertEqual(r["url"], "https://old.example/x")

    def test_a_numeric_service_worker_id_is_not_shown_as_a_url(self):
        r = self.row(b"7")
        self.assertIsNone(r["url"])
        self.assertEqual(r["key"], "7")
        self.assertEqual(r["note"], "key has no URL: 7")
        self.assertEqual(r["status"], 200)

    def test_a_partitioned_key_with_no_separator_gives_no_url(self):
        r = self.row(b"1/0/_dk_https://top.example")
        self.assertIsNone(r["url"])
        self.assertEqual(r["note"], "key has no URL: 1/0/_dk_https://top.example")

    def test_a_key_that_does_not_end_in_a_url_gives_no_url(self):
        self.assertIsNone(self.row(b"1/0/not a url")["url"])


class ChromiumCodeCache(unittest.TestCase):
    """Chromium's V8 code cache uses the same file formats as the HTTP
    cache but holds script bytecode, not web content; it must not be
    listed as cached pages."""

    def test_code_cache_files_are_not_cache_entries(self):
        for path in ("/Users/u/AppData/Local/Google/Chrome/User Data/"
                     "Default/Code Cache/js/0123456789abcdef_0",
                     "/p/Default/Code Cache/wasm/0123456789abcdef_0",
                     "/p/Default/Code Cache/js/index-dir/the-real-index",
                     "/p/Default/Storage/ext/x/def/Code Cache/js/"
                     "0123456789abcdef_0"):
            name = path.rsplit("/", 1)[1]
            self.assertIsNone(bc.classify({"name": name, "path": path}),
                              path)

    def test_the_http_cache_beside_it_is_still_classified(self):
        self.assertEqual(
            bc.classify({"name": "0123456789abcdef_0",
                         "path": "/p/Default/Cache/Cache_Data/"
                                 "0123456789abcdef_0"}), "chromium")
        self.assertEqual(
            bc.classify({"name": "data_1",
                         "path": "/p/Default/Cache/Cache_Data/data_1"}),
            "blockfile")
        self.assertEqual(
            bc.classify({"name": "the-real-index",
                         "path": "/p/Default/Cache/Cache_Data/index-dir/"
                                 "the-real-index"}), "index")


class ParseCache2(unittest.TestCase):

    def test_row_carries_url_status_and_timestamps(self):
        r = bc.parse_cache2_entry(cache2_entry())
        self.assertEqual(r["url"], "https://example.com/page")
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["content_type"], "text/css")
        self.assertEqual(r["last_fetched"], "2023-11-14T22:13:20Z")
        self.assertEqual(r["last_modified"], "2023-07-22T04:26:40Z")
        self.assertEqual(r["fetched_count"], 7)
        self.assertEqual(r["source"], "firefox")

    def test_tagged_key_keeps_key_and_extracts_url(self):
        r = bc.parse_cache2_entry(
            cache2_entry(key=b"~id,p,:https://example.com/x"))
        self.assertEqual(r["url"], "https://example.com/x")
        self.assertEqual(r["key"], "~id,p,:https://example.com/x")

    def test_bare_scheme_key_is_the_url(self):
        r = bc.parse_cache2_entry(cache2_entry(key=b"https://example.com/p"))
        self.assertEqual(r["url"], "https://example.com/p")

    def test_version_1_header_is_28_bytes(self):
        r = bc.parse_cache2_entry(cache2_entry(version=1))
        self.assertEqual(r["url"], "https://example.com/page")
        self.assertEqual(r["fetched_count"], 7)

    def test_unknown_version_is_rejected(self):
        self.assertIsNone(bc.parse_cache2_entry(cache2_entry(version=9)))

    def test_odd_null_count_in_elements_is_rejected(self):
        bad = cache2_entry(elements=b"response-head\0HTTP/1.1 200 OK\r\n\r\n\0Z")
        self.assertIsNone(bc.parse_cache2_entry(bad))

    def test_corrupted_metadata_hash_still_parses(self):
        data = bytearray(cache2_entry())
        data[300] ^= 0xFF  # the metadata hash is never verified
        r = bc.parse_cache2_entry(bytes(data))
        self.assertEqual(r["url"], "https://example.com/page")

    def test_key_without_a_scheme_is_reported(self):
        r = bc.parse_cache2_entry(cache2_entry(key=b"not-a-url-key"))
        self.assertIsNone(r["url"])
        self.assertIn("key has no URL", r["note"])


class Classify(unittest.TestCase):

    @staticmethod
    def entry(name, path):
        return {"name": name, "path": path}

    def test_chromium_entry_names(self):
        self.assertEqual(
            bc.classify(self.entry("0123456789abcdef_0",
                                   "/u/Chrome/Cache/Cache_Data/"
                                   "0123456789abcdef_0")),
            "chromium")

    def test_stream_1_files_are_not_parsed(self):
        self.assertIsNone(
            bc.classify(self.entry("0123456789abcdef_1",
                                   "/u/Chrome/Cache/Cache_Data/"
                                   "0123456789abcdef_1")))

    def test_40_hex_outside_cache2_is_ignored(self):
        self.assertIsNone(
            bc.classify(self.entry("a" * 40, "/u/whatever/" + "a" * 40)))

    def test_40_hex_under_cache2_is_firefox(self):
        self.assertEqual(
            bc.classify(self.entry("a" * 40,
                                   "/u/Firefox/cache2/entries/aa/bb/"
                                   + "a" * 40)),
            "firefox")

    def test_blockfile_names_need_cache_in_the_path(self):
        e = self.entry("f_000001", "/u/Chrome/Cache/Cache_Data/f_000001")
        self.assertEqual(bc.classify(e), "blockfile")
        e = self.entry("data_1", "/u/Chrome/Cache/Cache_Data/data_1")
        self.assertEqual(bc.classify(e), "blockfile")
        e = self.entry("data_1", "/u/elsewhere/data_1")
        self.assertIsNone(bc.classify(e))

    def test_the_real_index_is_the_index(self):
        self.assertEqual(
            bc.classify(self.entry(
                "the-real-index",
                "/u/Chrome/Cache/Cache_Data/index-dir/the-real-index")),
            "index")

    def test_browser_databases_are_not_cache(self):
        self.assertIsNone(
            bc.classify(self.entry("history",
                                   "/u/Chrome/User Data/Default/History")))
        self.assertIsNone(
            bc.classify(self.entry("places.sqlite", "/u/Firefox/places.sqlite")))

    def test_classification_is_case_insensitive(self):
        self.assertEqual(
            bc.classify(self.entry("ABCDEF0123456789_0",
                                   "/u/Chrome/Cache_Data/ABCDEF0123456789_0")),
            "chromium")


class FakeFs:
    """listdir is never reached by collect(); only read_file is used."""

    def __init__(self, files):
        self.files = files

    def read_file(self, entry, max_bytes=None, stream=""):
        return self.files.get(entry["path"], b"")


def entry_for(path, size=None):
    data = {"name": path.rsplit("/", 1)[-1], "path": path,
            "is_dir": False, "size": size if size is not None else 100}
    return data


class Collect(unittest.TestCase):

    def build_tree(self):
        chrome = "C/Users/jane/AppData/Local/Google/Chrome/User Data/" \
                 "Default/Cache/Cache_Data"
        firefox = "C/Users/jane/AppData/Local/Mozilla/Firefox/Profiles/" \
                  "x.default/cache2/entries/ab/cd"
        files = {
            "%s/0123456789abcdef_0" % chrome:
                simple_entry(url=b"https://chromium.example/one"),
            "%s/%s" % (firefox, "b" * 40):
                cache2_entry(key=b":https://firefox.example/two"),
        }
        entries = [
            entry_for(files, "%s/0123456789abcdef_0" % chrome),
            entry_for(files, "%s/data_1" % chrome),
            entry_for(files, "%s/the-real-index" % chrome.replace(
                "Cache_Data", "Cache_Data/index-dir")),
            entry_for(files, "%s/%s" % (firefox, "b" * 40)),
            entry_for(files, "%s/deadbeefcafe0123_0" % chrome),
            entry_for(files, "C/notes.txt"),
        ]
        return FakeFs(files), entries

    def test_rows_counters_and_findings(self):
        fs, entries = self.build_tree()
        out = bc.collect(fs, entries)
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["skipped"], 1)
        self.assertEqual(out["blockfile"], 1)
        self.assertTrue(out["index_present"])
        self.assertEqual(len(out["rows"]), 2)
        by_url = {r["url"]: r for r in out["rows"]}
        chrome = by_url["https://chromium.example/one"]
        ff = by_url["https://firefox.example/two"]
        self.assertEqual(chrome["product"], "Chrome")
        self.assertEqual(ff["product"], "Firefox")
        self.assertEqual(chrome["path"], entries[0]["path"])
        self.assertEqual(ff["fetched_count"], 7)
        self.assertEqual(len(out["findings"]), 3)
        joined = " ".join(out["findings"])
        self.assertIn("blockfile", joined)
        self.assertIn("the-real-index", joined)
        self.assertIn("could not be read or parsed", joined)

    def test_limit_stops_parsing_but_keeps_counters(self):
        files = {
            "/c/Cache_Data/0123456789abcdef_0":
                simple_entry(url=b"https://a.example/1"),
            "/c/Cache_Data/1111111111111111_0":
                simple_entry(url=b"https://b.example/2"),
        }
        entries = [entry_for(files, "/c/Cache_Data/0123456789abcdef_0"),
                   entry_for(files, "/c/Cache_Data/1111111111111111_0")]
        reads = []

        class CountingFs(FakeFs):
            def read_file(self, entry, max_bytes=None, stream=""):
                reads.append(entry["path"])
                return super().read_file(entry, max_bytes, stream)

        out = bc.collect(CountingFs(files), entries, limit=1)
        self.assertEqual(out["count"], 1)
        self.assertEqual(len(out["rows"]), 1)
        self.assertEqual(out["rows"][0]["url"], "https://a.example/1")
        # The second entry is never read once the limit is reached...
        self.assertEqual(reads, ["/c/Cache_Data/0123456789abcdef_0"])
        # ...but the cap still shows in skipped.
        self.assertEqual(out["skipped"], 1)
        self.assertIn("could not be read or parsed", " ".join(out["findings"]))

    def test_oversized_entries_are_skipped_without_a_read(self):
        files = {}
        path = "/c/Cache_Data/0123456789abcdef_0"
        reads = []

        class CountingFs(FakeFs):
            def read_file(self, entry, max_bytes=None, stream=""):
                reads.append(entry["path"])
                return super().read_file(entry, max_bytes, stream)

        entry = entry_for(files, path, size=bc.READ_CAP + 1)
        out = bc.collect(CountingFs(files), [entry])
        self.assertEqual(out["count"], 0)
        self.assertEqual(out["skipped"], 1)
        self.assertEqual(reads, [])

    def test_empty_walk_gives_no_findings(self):
        out = bc.collect(FakeFs({}), [])
        self.assertEqual(out["rows"], [])
        self.assertEqual(out["count"], 0)
        self.assertEqual(out["skipped"], 0)
        self.assertEqual(out["blockfile"], 0)
        self.assertFalse(out["index_present"])
        self.assertEqual(out["findings"], [])


def entry_for(files, path, size=None):
    data = files.get(path)
    return {"name": path.rsplit("/", 1)[-1], "path": path,
            "is_dir": False,
            "size": size if size is not None else (len(data) if data else 100)}


if __name__ == "__main__":
    unittest.main()