"""Tests for engine.blockfilecache and the blockfile path of
engine.browsercache: Chromium's legacy HTTP cache (data_0..data_3,
f_XXXXXX). Every byte fixture is built here in code from the layouts in
Chromium's disk_format_base.h, disk_format.h and addr.h; the repo carries
no binary test fixtures."""

import struct
import unittest

from engine import blockfilecache as bf
from engine import browsercache as bc

CACHE = ("C/Users/jane/AppData/Local/Google/Chrome/User Data/Default/"
         "Cache/Cache_Data")
# 2023-11-14T22:13:20Z as microseconds since 1601-01-01
T0 = (1700000000 + 11644473600) * 10 ** 6
T0_ISO = "2023-11-14T22:13:20Z"

# "BaseHTTP/0.6" holds an "HTTP/" that is not a status line; real servers
# send such headers and the status must still come from the first line.
HEADERS = (b"HTTP/1.1 200 OK\0Server: BaseHTTP/0.6 Python/3.14\0"
           b"Content-Type: text/html\0Content-Length: 4\0\0")


def addr(ftype, number=0, start=0, blocks=1):
    """CacheAddr: initialised bit, file type, block count, file, block."""
    if ftype == bf.FILE_EXTERNAL:
        return 0x80000000 | number
    return (0x80000000 | ftype << 28 | (blocks - 1) << 24
            | number << 16 | start)


def response_pickle(headers=HEADERS, request=T0 - 5 * 10 ** 6, response=T0,
                    extra=None, cut=None):
    """Stream 0: an HttpResponseInfo Pickle, version 3."""
    body = struct.pack("<I", 3 | (0x80000000 if extra is not None else 0))
    if extra is not None:
        body += struct.pack("<I", extra)
    body += struct.pack("<qq", request, response)
    if extra is not None and extra & 4:
        body += struct.pack("<q", response - 10 ** 6)
    body += struct.pack("<i", len(headers)) + headers
    body += b"\0" * (-len(headers) % 4)
    data = struct.pack("<I", len(body)) + body
    return data if cut is None else data[:cut]


def entry_record(key, rank, streams, state=0, created=T0, refetch=2,
                 long_key=0, key_len=None):
    """EntryStore: 96 bytes then the inline key, padded to whole blocks.
    streams: four (size, address) pairs."""
    raw = key.encode() if isinstance(key, str) else key
    klen = len(raw) if key_len is None else key_len
    fixed = bf._ENTRY.pack(
        0xABCD, 0, rank, 1, refetch, state, created, klen, long_key,
        *[s for s, _ in streams], *[a for _, a in streams],
        0, 0, 0, 0, 0, 0)
    inline = raw + b"\0" if long_key == 0 else b""
    rec = fixed + inline
    return rec + b"\0" * (-len(rec) % bf.ENTRY_BLOCK)


def rankings_node(last_used=T0 + 60 * 10 ** 6):
    return bf._RANKINGS.pack(last_used, T0, 0, 0, 0, 0, 0)


def block_file(block_size, blocks, total, used=None, this_file=0):
    """A block file: 8192-byte header + bitmap, then `total` blocks.
    blocks: {first block index: bytes}. used: block indexes marked
    allocated (defaults to every block that has content)."""
    if used is None:
        used = set()
        for start, data in blocks.items():
            used.update(range(start, start + -(-len(data) // block_size)))
    header = struct.pack("<IIhhiii4i4ii5i", bf.BLOCK_MAGIC, 0x20000,
                         this_file, 0, block_size, len(used), total,
                         *([0] * 14))       # empty, hints, updating, user
    bitmap = bytearray(bf.HEADER_SIZE - len(header))
    for b in used:
        bitmap[b // 8] |= 1 << (b % 8)
    body = bytearray(total * block_size)
    for start, data in blocks.items():
        body[start * block_size:start * block_size + len(data)] = data
    return header + bytes(bitmap) + bytes(body)


class Mem:
    def __init__(self, data):
        self.data, self.size = data, len(data)

    def read_at(self, offset, length):
        return self.data[offset:offset + length]


def cache_folder(entries, body=b"BODY", extra_files=None, data1_used=None):
    """Files of a folder holding `entries`, a list of (key, kwargs).
    Entry i sits in data_1 block i; its rankings node is data_0 block i,
    stream 0 in data_2 block i, the body in data_3 block i."""
    d0, d1, d2, d3 = {}, {}, {}, {}
    for i, (key, kw) in enumerate(entries):
        s0 = kw.pop("stream0", response_pickle())
        d0[i] = rankings_node()
        d2[i] = s0
        d3[i] = body
        streams = [(len(s0), addr(3, 2, i)), (len(body), addr(4, 3, i)),
                   (0, 0), (0, 0)]
        d1[i] = entry_record(key, addr(bf.FILE_RANKINGS, 0, i), streams,
                             **kw)
    n = len(entries) + 1
    files = {
        "data_0": block_file(36, d0, n),
        "data_1": block_file(256, d1, n, used=data1_used),
        "data_2": block_file(1024, d2, n),
        "data_3": block_file(4096, d3, n),
        "index": struct.pack("<I", 0xC103CAC3) + bytes(364),
    }
    files.update(extra_files or {})
    return files


def mem(files):
    return {k: Mem(v) for k, v in files.items()}


class Layout(unittest.TestCase):

    def test_structure_sizes_match_the_format(self):
        self.assertEqual(bf._ENTRY.size, 96)
        self.assertEqual(bf._RANKINGS.size, 36)
        self.assertEqual(bf._HEADER.size, 80)

    def test_addresses_decode(self):
        self.assertIsNone(bf.decode_addr(0))
        self.assertEqual(bf.decode_addr(addr(3, 2, 7, 3)), (3, 2, 7, 3))
        self.assertEqual(bf.decode_addr(addr(0, 0x1234)), (0, 0x1234, 0, 0))
        # file type 5..7 does not exist
        self.assertIsNone(bf.decode_addr(0x80000000 | 5 << 28))

    def test_chromium_time(self):
        self.assertEqual(bf.chromium_time(T0), T0_ISO.replace("Z", "") + "Z")
        self.assertIsNone(bf.chromium_time(0))
        self.assertIsNone(bf.chromium_time(5))


class Entries(unittest.TestCase):

    def parse(self, files):
        return bf.entries(bf.Files(mem(files)))

    def test_entry_is_found_with_streams_and_counts(self):
        files = cache_folder([("1/0/https://example.com/a", {})])
        found, sparse = self.parse(files)
        self.assertEqual(sparse, 0)
        self.assertEqual(len(found), 1)
        e = found[0]
        self.assertEqual(e["key"], "1/0/https://example.com/a")
        self.assertIsNone(e["state"])
        self.assertTrue(e["allocated"])
        self.assertEqual(e["created"], T0)
        self.assertEqual(e["last_used"], T0 + 60 * 10 ** 6)
        self.assertEqual(e["refetch_count"], 2)
        self.assertEqual(e["sizes"][1], 4)
        self.assertEqual(e["file"], "data_1")
        self.assertEqual(e["offset"], bf.HEADER_SIZE)

    def test_response_pickle_is_decoded(self):
        req, resp, lines = bf._response(response_pickle())
        self.assertEqual(resp, T0)
        self.assertEqual(lines[0], b"HTTP/1.1 200 OK")
        self.assertIn(b"Content-Type: text/html", lines)

    def test_extra_flags_and_original_response_time_are_skipped(self):
        # extra bit 2 adds an int64 before the headers
        req, resp, lines = bf._response(response_pickle(extra=4))
        self.assertEqual(resp, T0)
        self.assertEqual(lines[0], b"HTTP/1.1 200 OK")

    def test_truncated_or_wrong_version_pickle_is_none(self):
        self.assertIsNone(bf._response(response_pickle(cut=30)))
        bad = bytearray(response_pickle())
        bad[4] = 2                                     # version 2
        self.assertIsNone(bf._response(bytes(bad)))
        self.assertIsNone(bf._response(None))
        self.assertIsNone(bf._response(b""))

    def test_doomed_and_evicted_entries_are_kept_and_marked(self):
        files = cache_folder([("1/0/https://a.example/", {"state": 2}),
                              ("1/0/https://b.example/", {"state": 1})])
        found, _ = self.parse(files)
        self.assertEqual([e["state"] for e in found], ["doomed", "evicted"])

    def test_freed_block_is_still_recovered_but_flagged(self):
        files = cache_folder([("1/0/https://gone.example/", {})],
                             data1_used=set())
        found, _ = self.parse(files)
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0]["allocated"])

    def test_sparse_child_entries_are_counted_not_listed(self):
        files = cache_folder([("Range_1234_5", {}),
                              ("1/0/https://example.com/", {})])
        found, sparse = self.parse(files)
        self.assertEqual(sparse, 1)
        self.assertEqual([e["key"] for e in found],
                         ["1/0/https://example.com/"])

    def test_key_longer_than_the_entry_lives_in_an_external_file(self):
        key = "1/0/https://example.com/" + "q" * 1200
        files = cache_folder([(key, {"long_key": addr(0, 0x2A),
                                     "key_len": len(key)})],
                             extra_files={"f_00002a": key.encode() + b"\0"})
        found, _ = self.parse(files)
        self.assertEqual([e["key"] for e in found], [key])

    def test_key_spanning_several_blocks(self):
        key = "1/0/https://example.com/" + "p" * 500
        files = cache_folder([(key, {})])
        # an entry with a 500-byte key occupies three 256-byte blocks
        found, _ = self.parse(files)
        self.assertEqual([e["key"] for e in found], [key])

    def test_incoherent_records_are_ignored(self):
        files = cache_folder([("1/0/https://ok.example/", {}),
                              ("1/0/https://old.example/", {"created": 5}),
                              ("1/0/https://st.example/", {"state": 9})])
        found, _ = self.parse(files)
        self.assertEqual([e["key"] for e in found],
                         ["1/0/https://ok.example/"])

    def test_junk_and_missing_files_are_harmless(self):
        self.assertEqual(self.parse({}), ([], 0))
        self.assertEqual(self.parse({"data_1": b"\xff" * 20000}), ([], 0))
        # a file truncated inside its header
        files = cache_folder([("1/0/https://x.example/", {})])
        files["data_1"] = files["data_1"][:100]
        self.assertEqual(self.parse(files), ([], 0))

    def test_missing_stream_files_leave_a_row_without_headers(self):
        files = cache_folder([("1/0/https://x.example/", {})])
        del files["data_2"]
        found, _ = self.parse(files)
        self.assertEqual(len(found), 1)
        self.assertIsNone(found[0]["stream0"])


class Rows(unittest.TestCase):

    def test_row_fields(self):
        files = cache_folder([("1/0/https://example.com/page", {})])
        rows, _ = bc.parse_blockfile_folder(mem(files), CACHE)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["url"], "https://example.com/page")
        self.assertEqual(r["key"], "1/0/https://example.com/page")
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["content_type"], "text/html")
        self.assertEqual(r["last_fetched"], T0_ISO.replace("Z", "") + "Z")
        self.assertEqual(r["fetched_count"], 2)
        self.assertEqual(r["source"], "chromium")
        self.assertEqual(r["format"], "blockfile")
        self.assertEqual(r["size"], 4)
        self.assertEqual(r["product"], "Chrome")
        self.assertTrue(r["path"].endswith("/data_1"))
        self.assertIsNone(r["note"])

    def test_partitioned_key_gives_the_resource_url(self):
        key = "1/0/_dk_https://top.example https://top.example " \
              "https://cdn.example/x.js"
        rows, _ = bc.parse_blockfile_folder(
            mem(cache_folder([(key, {})])), CACHE)
        self.assertEqual(rows[0]["url"], "https://cdn.example/x.js")

    def test_notes_say_doomed_deleted_and_no_url(self):
        files = cache_folder([("1/0/https://a.example/", {"state": 2}),
                              ("0", {})], data1_used=set())
        rows, _ = bc.parse_blockfile_folder(mem(files), CACHE)
        by_key = {r["key"]: r for r in rows}
        self.assertIn("doomed", by_key["1/0/https://a.example/"]["note"])
        self.assertIn("not allocated",
                      by_key["1/0/https://a.example/"]["note"])
        self.assertIsNone(by_key["0"]["url"])
        self.assertIn("no URL", by_key["0"]["note"])

    def test_unreadable_response_info_keeps_the_row(self):
        files = cache_folder([("1/0/https://x.example/",
                               {"stream0": response_pickle(cut=20)})])
        rows, _ = bc.parse_blockfile_folder(mem(files), CACHE)
        self.assertEqual(rows[0]["url"], "https://x.example/")
        self.assertIsNone(rows[0]["status"])
        self.assertIn("could not be read", rows[0]["note"])


class RangeFs:
    def __init__(self, files):
        self.files = files
        self.ranged = 0

    def read_file(self, entry, max_bytes=None, stream=""):
        return self.files[entry["path"]][:max_bytes]

    def read_range(self, entry, offset, length):
        self.ranged += 1
        return self.files[entry["path"]][offset:offset + length]


class WholeFileFs:
    """Like NTFS here: no read_range, so the file is read once."""

    def __init__(self, files):
        self.files = files
        self.reads = 0

    def read_file(self, entry, max_bytes=None, stream=""):
        self.reads += 1
        return self.files[entry["path"]][:max_bytes]


class CollectBlockfile(unittest.TestCase):

    def tree(self):
        folder = cache_folder([("1/0/https://example.com/a", {}),
                               ("1/0/https://example.com/b", {})])
        files = {"%s/%s" % (CACHE, k): v for k, v in folder.items()}
        entries = [{"name": p.rsplit("/", 1)[-1], "path": p,
                    "is_dir": False, "size": len(v)}
                   for p, v in files.items()]
        return files, entries

    def test_collect_lists_entries_and_reports_them(self):
        files, entries = self.tree()
        out = bc.collect(RangeFs(files), entries)
        self.assertEqual(sorted(r["url"] for r in out["rows"]),
                         ["https://example.com/a", "https://example.com/b"])
        self.assertEqual(out["blockfile"], 5 - 1)      # index is not counted
        self.assertTrue(any("blockfile" in f and "2 entries" in f
                            for f in out["findings"]))
        self.assertFalse(any("not parsed" in f and "blockfile" in f
                             for f in out["findings"]))

    def test_filesystems_without_read_range_read_each_file_once(self):
        files, entries = self.tree()
        fs = WholeFileFs(files)
        out = bc.collect(fs, entries)
        self.assertEqual(len(out["rows"]), 2)
        self.assertLessEqual(fs.reads, 5)

    def test_ranged_reads_avoid_whole_file_reads(self):
        files, entries = self.tree()
        fs = RangeFs(files)
        bc.collect(fs, entries)
        self.assertGreater(fs.ranged, 0)

    def test_empty_files_and_directories_are_not_counted_or_read(self):
        entries = [
            {"name": "data_1", "path": "%s/data_1" % CACHE,
             "is_dir": False, "size": 0},
            {"name": "f_000002", "path": "%s/f_000002" % CACHE,
             "is_dir": True, "size": 4096},
            {"name": "0123456789abcdef_0", "path": "%s/0123456789abcdef_0"
             % CACHE, "is_dir": False, "size": 0},
        ]
        out = bc.collect(RangeFs({}), entries)
        self.assertEqual((out["rows"], out["skipped"], out["blockfile"]),
                         ([], 0, 0))
        self.assertEqual(out["findings"], [])

    def test_cache_folder_of_junk_does_not_raise(self):
        files = {"%s/data_1" % CACHE: b"\x01" * 9000}
        entries = [{"name": "data_1", "path": "%s/data_1" % CACHE,
                    "is_dir": False, "size": 9000}]
        out = bc.collect(RangeFs(files), entries)
        self.assertEqual(out["rows"], [])


if __name__ == "__main__":
    unittest.main()
