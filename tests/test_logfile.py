"""The $LogFile parser (engine.logfile), fed synthetic logs from
imagebuild_logfile. The builder follows ntfs-3g's structure description;
there is no real $LogFile in the repository to check either against."""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import imagebuild_logfile as b                                # noqa: E402
import imagebuild_ntfs as ntfs                                # noqa: E402
from engine import logfile                                    # noqa: E402
from engine.ewf import OffsetReader                           # noqa: E402
from engine.fs.ntfs import open_fs                            # noqa: E402


def setUpModule():
    # The route test starts its own server; the notes API tests keep a shared
    # one whose port must be looked up again afterwards.
    import test_notes_api
    test_notes_api._PORT.clear()


def parse(data, **kw):
    return logfile.parse(lambda off, n: data[off:off + n], len(data), **kw)


ENTRY = b.index_entry(20, "secret.doc")
SPECS = [
    dict(redo_op=0x0E, undo_op=0x0F, redo=ENTRY, undo=ENTRY, tx=5, attr=3,
         lcns=[100], vcn=2),
    dict(redo_op=0x13, undo_op=0x13, redo=b.file_name("renamed.txt"),
         undo=b.file_name("original.txt"), tx=6),
    dict(redo_op=0x1A, undo_op=0x00, tx=5),
    dict(type="checkpoint"),
]


class Restart(unittest.TestCase):

    def test_restart_area_fields(self):
        data, _ = b.logfile(SPECS)
        report, _recs = parse(data)
        self.assertEqual(len(report["restart"]), 2)
        r = report["restart"][0]
        self.assertTrue(r["valid"])
        self.assertEqual(r["version"], "1.1")
        self.assertTrue(r["clean_shutdown"])
        self.assertEqual(r["client_names"], ["NTFS"])
        self.assertEqual(r["seq_number_bits"], b.SEQ_BITS)
        self.assertEqual(r["open_count"], 1)
        self.assertEqual(report["findings"], [])

    def test_unclean_shutdown_is_a_finding(self):
        data, _ = b.logfile(SPECS, clean=False)
        report, _ = parse(data)
        self.assertTrue(any("did not shut down cleanly" in f
                            for f in report["findings"]))

    def test_one_torn_restart_page_leaves_the_other(self):
        data, _ = b.logfile(SPECS)
        torn = bytearray(data)
        torn[b.SECTOR - 2:b.SECTOR] = b"\x00\x00"
        report, recs = parse(bytes(torn))
        self.assertEqual(report["stats"]["restart_pages"], 1)
        self.assertEqual(report["newest_restart"], 1)
        self.assertEqual(len(recs), 4)

    def test_no_usable_restart_page_is_refused(self):
        data, _ = b.logfile(SPECS)
        torn = bytearray(data)
        for page in (0, 1):
            torn[page * b.PAGE + b.SECTOR - 2:page * b.PAGE + b.SECTOR] = \
                b"\x00\x00"
        with self.assertRaises(logfile.LogFileError):
            parse(bytes(torn))
        with self.assertRaises(logfile.LogFileError):
            parse(bytes(3 * b.PAGE))

    def test_unexpected_page_size_is_a_finding(self):
        data, _ = b.logfile(SPECS)
        data = b.restart_page(1, page_size=8192) * 2 + data[2 * b.PAGE:]
        report, _ = parse(data)
        self.assertTrue(any("8192" in f for f in report["findings"]))


class Records(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data, cls.starts = b.logfile(SPECS)
        cls.report, cls.recs = parse(cls.data)

    def test_records_are_found_in_lsn_order(self):
        self.assertEqual([r["offset"] for r in self.recs], self.starts)
        self.assertEqual([r["lsn"] for r in self.recs],
                         sorted(r["lsn"] for r in self.recs))
        self.assertEqual([r["type"] for r in self.recs],
                         ["standard"] * 3 + ["checkpoint"])

    def test_operation_fields(self):
        r = self.recs[0]
        self.assertEqual((r["redo_op"], r["redo_name"]), (0x0E, "AddIndexEntryAllocation"))
        self.assertEqual((r["undo_op"], r["undo_name"]), (0x0F, "DeleteIndexEntryAllocation"))
        self.assertEqual(r["transaction"], 5)
        self.assertEqual(r["target_attribute"], 3)
        self.assertEqual(r["target_vcn"], 2)
        self.assertEqual(r["lcns"], [100])
        self.assertEqual(self.recs[2]["redo_name"], "CommitTransaction")

    def test_unknown_operation_keeps_its_code(self):
        data, _ = b.logfile([dict(redo_op=0x7F, undo_op=0)])
        _, recs = parse(data)
        self.assertEqual((recs[0]["redo_op"], recs[0]["redo_name"]),
                         (0x7F, "unknown"))

    def test_lsn_position_matches_where_the_record_lies(self):
        self.assertTrue(all(r["lsn_position_matches"] for r in self.recs))
        self.assertEqual(self.report["stats"]["position_matches"], 4)
        data, _ = b.logfile([dict(redo_op=0, undo_op=0, lsn_shift=8)])
        report, recs = parse(data)
        self.assertFalse(recs[0]["lsn_position_matches"])
        self.assertEqual(report["stats"]["position_matches"], 0)

    def test_stats(self):
        st = self.report["stats"]
        self.assertEqual((st["records"], st["log_pages"], st["unused_pages"]),
                         (4, 1, 5))
        self.assertEqual(st["transactions"], 2)
        self.assertEqual(st["first_lsn"], self.recs[0]["lsn"])

    def test_no_sequence_is_reconstructed(self):
        for r in self.recs:
            for key in r:
                self.assertNotIn(key, ("timeline", "event", "summary"))


class Names(unittest.TestCase):

    def test_index_entry_payloads_give_name_times_and_references(self):
        _, recs = parse(b.logfile(SPECS)[0])
        got = recs[0]["names"]
        self.assertEqual([(n["from"], n["name"]) for n in got],
                         [("redo", "secret.doc"), ("undo", "secret.doc")])
        n = got[0]
        self.assertEqual((n["file_reference"], n["file_sequence"]), (20, 3))
        self.assertEqual((n["parent_reference"], n["parent_sequence"]), (5, 1))
        self.assertEqual(n["source"], "index entry")
        self.assertEqual(n["times"]["created"], "2019-05-05T05:05:05Z")

    def test_update_file_name_payload_is_the_bare_attribute(self):
        _, recs = parse(b.logfile(SPECS)[0])
        got = recs[1]["names"]
        self.assertEqual([(n["from"], n["name"], n["source"]) for n in got],
                         [("redo", "renamed.txt", "$FILE_NAME"),
                          ("undo", "original.txt", "$FILE_NAME")])

    def test_a_name_is_not_taken_from_an_operation_that_does_not_carry_one(self):
        data, _ = b.logfile([dict(redo_op=0x07, undo_op=0x07, redo=ENTRY,
                                  undo=ENTRY)])
        _, recs = parse(data)
        self.assertNotIn("names", recs[0])

    def test_implausible_payloads_give_no_name(self):
        bad_time = bytearray(ENTRY)
        bad_time[16 + 8:16 + 16] = b"\xff" * 8
        short_key = bytearray(ENTRY)
        short_key[10:12] = b"\x10\x00"
        control = bytearray(ENTRY)
        control[16 + 66:16 + 68] = b"\x01\x00"
        overrun = bytearray(ENTRY)
        overrun[16 + 64] = 200
        for payload in (bytes(bad_time), bytes(short_key), bytes(control),
                        bytes(overrun), ENTRY[:30], bytes(80)):
            data, _ = b.logfile([dict(redo_op=0x0C, undo_op=0x0D,
                                      redo=payload)])
            _, recs = parse(data)
            self.assertNotIn("names", recs[0], payload[:12])

    def test_stats_count_names(self):
        report, _ = parse(b.logfile(SPECS)[0])
        self.assertEqual(report["stats"]["names"], 4)


class Pages(unittest.TestCase):

    def specs(self, n):
        return [dict(redo_op=0x0E, undo_op=0x0F, tx=i + 1,
                     redo=b.index_entry(30 + i, "file%d.txt" % i),
                     undo=b.index_entry(30 + i, "file%d.txt" % i))
                for i in range(n)]

    def test_records_that_run_into_the_next_page_are_joined(self):
        specs = self.specs(40)
        data, starts = b.logfile(specs, log_pages=6)
        report, recs = parse(data)
        self.assertGreater(report["stats"]["log_pages"], 2)
        self.assertEqual([r["offset"] for r in recs], starts)
        self.assertTrue(all(r["lsn_position_matches"] for r in recs))
        self.assertEqual([n["name"] for r in recs for n in r["names"][:1]],
                         ["file%d.txt" % i for i in range(40)])
        # at least one record really straddles a page boundary
        self.assertTrue(any((s % b.PAGE) + 300 > b.PAGE for s in starts))
        self.assertEqual(report["stats"]["incomplete"], 0)

    def test_torn_log_page_is_skipped_and_reported(self):
        data, _ = b.logfile(self.specs(40), log_pages=6)
        good, _ = parse(data)
        data, _ = b.logfile(self.specs(40), log_pages=6, tear_page=1)
        report, recs = parse(data)
        self.assertEqual(report["stats"]["torn_pages"], 1)
        self.assertLess(len(recs), good["stats"]["records"])
        self.assertTrue(any("update sequence check" in f
                            for f in report["findings"]))

    def test_unused_and_foreign_pages_are_counted_not_parsed(self):
        data, _ = b.logfile(SPECS, log_pages=6)
        data = bytearray(data)
        at = 4 * b.PAGE
        data[at:at + 4] = b"ABCD"
        report, recs = parse(bytes(data))
        st = report["stats"]
        self.assertEqual((st["unused_pages"], st["unrecognised_pages"]),
                         (4, 1))
        self.assertEqual(len(recs), 4)

    def test_record_cap_is_reported(self):
        old = logfile.MAX_RECORDS
        logfile.MAX_RECORDS = 3
        try:
            report, recs = parse(b.logfile(self.specs(10))[0])
        finally:
            logfile.MAX_RECORDS = old
        self.assertEqual(len(recs), 3)
        self.assertTrue(report["stats"]["truncated"])
        self.assertTrue(any("not listed" in f for f in report["findings"]))

    def test_progress_is_reported_and_bounded(self):
        calls = []
        data, _ = b.logfile(SPECS)
        parse(data * 1, progress=calls.append)
        self.assertTrue(all(0 <= c <= 1 for c in calls))


class Damage(unittest.TestCase):

    def test_random_damage_never_raises_anything_but_logfile_error(self):
        data, _ = b.logfile(SPECS + Pages.specs(None, 30), log_pages=6)
        rng = random.Random(4)
        for _ in range(400):
            mutated = bytearray(data)
            for _ in range(rng.randint(1, 30)):
                mutated[rng.randrange(len(mutated))] = rng.randrange(256)
            if rng.random() < 0.2:
                mutated = mutated[:rng.randrange(len(mutated))]
            try:
                parse(bytes(mutated))
            except logfile.LogFileError:
                pass


class OnAVolume(unittest.TestCase):

    def test_read_through_an_ntfs_volume(self):
        data, _ = b.logfile(SPECS, log_pages=4)
        img = b.ntfs_with_logfile(data)

        class Mem(object):
            bytes_per_sector = 512

            def __init__(self, d):
                self.d, self.size = d, len(d)

            def read_at(self, off, n):
                return self.d[off:off + n] if 0 <= off < self.size else b""

        fs = open_fs(OffsetReader(Mem(img), 0, len(img)))
        attr = logfile.find(fs)
        self.assertIsNotNone(attr)
        report, recs = logfile.read_volume(fs, attr)
        expect, _ = parse(data)
        self.assertEqual(report["stats"], expect["stats"])
        self.assertEqual([r["lsn"] for r in recs], [r["lsn"] for r in parse(data)[1]])
        self.assertEqual(recs[0]["names"][0]["name"], "secret.doc")

    def test_a_volume_whose_log_is_empty_is_refused_not_guessed(self):
        class Fs(object):
            def record(self, n):
                return None
        self.assertIsNone(logfile.find(Fs()))
        with self.assertRaises(logfile.LogFileError):
            parse(b"")


class Route(unittest.TestCase):
    """The artefact route, through the real server on an NTFS image."""

    def test_read_then_page_and_filter(self):
        import http.client
        import json
        import shutil
        import socket
        import tempfile
        import threading
        import time
        from engine import server

        d = tempfile.mkdtemp(prefix="strata-logfile-route-")
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        img = os.path.join(d, "disk.img")
        data, _ = b.logfile(SPECS, log_pages=4)
        with open(img, "wb") as fh:
            fh.write(b.ntfs_with_logfile(data))
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        ready = threading.Event()
        threading.Thread(target=server.serve, daemon=True, kwargs={
            "host": "127.0.0.1", "port": port,
            "on_ready": lambda h, p: ready.set()}).start()
        ready.wait(10)
        cookie = []

        def call(method, path, body=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            host = "127.0.0.1:%d" % port
            h = {"Content-Type": "application/json", "Host": host,
                 "Origin": "http://" + host}
            if cookie:
                h["Cookie"] = cookie[0]
            c.request(method, path, json.dumps(body) if body is not None
                      else None, h)
            r = c.getresponse()
            raw = r.read()
            if r.getheader("Set-Cookie"):
                cookie[:] = [r.getheader("Set-Cookie").split(";")[0]]
            c.close()
            if "json" in (r.getheader("Content-Type") or ""):
                return json.loads(raw)
            return None

        call("GET", "/")
        opened = call("POST", "/api/open", {
            "path": img, "case_path": os.path.join(d, "case"),
            "examiner": "T"})
        self.assertTrue(opened["open"], opened)
        self.assertFalse(call("GET", "/api/logfile")["loaded"])
        task = call("POST", "/api/logfile", {"part": 0})
        for _ in range(200):
            t = call("GET", "/api/task?id=" + task["id"])
            if t.get("state") != "running":
                break
            time.sleep(0.05)
        self.assertEqual(t["state"], "done", t)
        self.assertTrue(t["result"]["present"], t["result"])
        self.assertEqual(t["result"]["records"], 4)
        got = call("GET", "/api/logfile?limit=2")
        self.assertEqual((got["total"], len(got["records"])), (4, 2))
        self.assertIn("CommitTransaction", got["operations"])
        found = call("GET", "/api/logfile?q=renamed")
        self.assertEqual(found["total"], 1)
        only = call("GET", "/api/logfile?op=CommitTransaction")
        self.assertEqual(only["total"], 1)
        self.assertEqual(only["records"][0]["transaction"], 5)


if __name__ == "__main__":
    unittest.main()
