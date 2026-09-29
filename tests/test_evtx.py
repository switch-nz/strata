"""Windows event logs (engine.evtx): records decode with descriptions from
the bundled table, and a volume's logs merge into one timeline."""

import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import imagebuild_evtx as build                                  # noqa: E402
from engine import eventids, evtx                                # noqa: E402

SEC = "Microsoft-Windows-Security-Auditing"
SCM = "Service Control Manager"


def security_log():
    return build.build_log([
        build.event(4624, SEC, "2024-03-01T10:00:00.000Z",
                    data={"LogonType": 10, "TargetUserName": "bob"}),
        build.event(4688, SEC, "2024-03-01T10:05:00.000Z",
                    data={"NewProcessName": "C:\\\\Windows\\\\cmd.exe"}),
        build.event(1102, "Microsoft-Windows-Eventlog",
                    "2024-03-01T11:00:00.000Z"),
    ])


def system_log():
    return build.build_log([
        build.event(7045, SCM, "2024-03-01T10:02:00.000Z", channel="System",
                    data={"ServiceName": "evil"}),
        build.event(9999, "Some-Vendor-Agent", "2024-03-01T09:00:00.000Z",
                    channel="System"),
    ], dirty=True)


class Records(unittest.TestCase):

    def test_records_carry_system_fields_and_descriptions(self):
        r = evtx.parse(security_log())
        self.assertEqual(r["findings"], [])
        first = r["records"][0]
        self.assertEqual(first["event_id"], "4624")
        self.assertEqual(first["level"], "Information")
        self.assertEqual(first["provider"], SEC)
        self.assertEqual(first["created"], "2024-03-01T10:00:00.000Z")
        self.assertEqual(first["fields"]["Event/EventData/TargetUserName"],
                         "bob")
        self.assertEqual(
            first["description"],
            "An account logged on (logon type 10: remote interactive "
            "(Remote Desktop))")
        self.assertEqual(r["records"][2]["description"],
                         "The audit log was cleared")

    def test_same_id_from_another_provider_gets_no_description(self):
        self.assertIsNone(eventids.describe("Some-Vendor-Agent", 4624))
        self.assertEqual(eventids.describe("Microsoft-Windows-Sysmon", 1),
                         "Sysmon: process created")
        self.assertEqual(eventids.describe("Microsoft-Windows-Kernel-General",
                                           "1"),
                         "The system time was changed")

    def test_unrecognised_logon_type_is_said_so(self):
        self.assertIn("logon type 77: unrecognised",
                      eventids.describe(SEC, 4625, {"x/LogonType": "77"}))

    def test_not_an_event_log(self):
        self.assertIsNone(evtx.parse(b"MZ" + bytes(8000)))


class Sweep(unittest.TestCase):

    def logs(self, extra=()):
        return [("Security.evtx", "/Windows/System32/winevt/Logs/Security.evtx",
                 security_log),
                ("System.evtx", "/Windows/System32/winevt/Logs/System.evtx",
                 system_log)] + list(extra)

    def test_events_from_every_log_merge_in_time_order(self):
        r = evtx.sweep(self.logs())
        got = [(e["time"][11:16], e["event_id"], r["logs"][e["log"]]["name"])
               for e in r["events"]]
        self.assertEqual(got, [
            ("09:00", "9999", "System.evtx"),
            ("10:00", "4624", "Security.evtx"),
            ("10:02", "7045", "System.evtx"),
            ("10:05", "4688", "Security.evtx"),
            ("11:00", "1102", "Security.evtx"),
        ])
        self.assertEqual(r["total_events"], 5)
        self.assertFalse(r["truncated"])
        self.assertEqual(r["events"][2]["description"], "A service was installed")
        self.assertIsNone(r["events"][0]["description"])
        self.assertIn("not the message text", r["note"])

    def test_each_log_is_summarised(self):
        r = evtx.sweep(self.logs())
        sec, sys_ = r["logs"]
        self.assertEqual((sec["records"], sec["channel"]), (3, "Security"))
        self.assertEqual((sec["first"][11:16], sec["last"][11:16]),
                         ("10:00", "11:00"))
        self.assertTrue(sys_["dirty"])
        self.assertTrue(sys_["findings"])

    def test_unreadable_and_foreign_files_are_reported_not_dropped(self):
        def broken():
            raise OSError("run list points outside the volume")
        r = evtx.sweep(self.logs([
            ("Broken.evtx", "/x/Broken.evtx", broken),
            ("Renamed.evtx", "/x/Renamed.evtx", lambda: b"PK\x03\x04" * 50),
        ]))
        errors = {row["name"]: row.get("error") for row in r["logs"]}
        self.assertEqual(errors["Broken.evtx"],
                         "run list points outside the volume")
        self.assertIn("not an event log", errors["Renamed.evtx"])
        self.assertEqual(r["total_events"], 5)

    def test_past_the_cap_the_newest_are_kept_and_it_says_so(self):
        r = evtx.sweep(self.logs(), max_events=2)
        self.assertTrue(r["truncated"])
        self.assertEqual(r["total_events"], 5)
        self.assertEqual([e["event_id"] for e in r["events"]], ["4688", "1102"])

    def test_random_damage_never_crashes(self):
        import random
        good = bytearray(security_log())
        rng = random.Random(59)
        for trial in range(300):
            data = bytearray(good)
            for _ in range(8):
                i = rng.randrange(4096, 4096 + 2048)
                data[i] = rng.getrandbits(8)
            with self.subTest(trial=trial):
                evtx.sweep([("x.evtx", "/x.evtx", lambda d=bytes(data): d)])



class OddValues(unittest.TestCase):
    """Template values can arrive as types the record's neighbours do not
    use. One such record must not stop a log, or a whole volume's logs,
    being read."""

    def normal(self, eid=4624, minute=0):
        return build.template_event(eid, build.filetime(2024, 3, 1, 10, minute))

    def test_a_time_that_is_not_text_does_not_fail_the_sweep(self):
        odd = build.template_record([
            (0x06, struct.pack("<H", 4634)), (0x04, bytes([4])),
            (0x0A, struct.pack("<Q", 123456789))])        # UInt64, not a time
        good = build.template_log([self.normal(4624, 0), self.normal(4625, 5)])
        oddlog = build.template_log([self.normal(4624, 1), odd])
        r = evtx.sweep([("Security.evtx", "/Security.evtx", lambda: good),
                        ("Odd.evtx", "/Odd.evtx", lambda: oddlog)])
        self.assertEqual([l.get("error") for l in r["logs"]], [None, None])
        self.assertEqual(r["total_events"], 4)
        self.assertTrue(all(isinstance(e["time"], str) for e in r["events"]))
        times = [e["time"] for e in r["events"]]
        self.assertEqual(times, sorted(times))
        # The odd record falls back to when the log wrote it.
        odd_event = [e for e in r["events"] if str(e["event_id"]) == "4634"]
        self.assertEqual(len(odd_event), 1)
        self.assertTrue(odd_event[0]["time"].startswith("2024-03-01T09:"))

    def test_a_provider_that_is_an_array_still_reads_and_has_no_description(self):
        data = build.template_log([
            build.template_record([
                (0x06, struct.pack("<H", 4624)), (0x04, bytes([4])),
                (0x11, struct.pack("<Q", build.filetime(2024, 3, 1, 10, 0))),
                (0x81, "A\x00B\x00".encode("utf-16-le"))])],
            provider=None)
        r = evtx.parse(data)
        self.assertEqual(len(r["records"]), 1)
        self.assertEqual(r["records"][0]["event_id"], 4624)
        self.assertIsNone(r["records"][0]["description"])
        self.assertIsNone(eventids.describe(["A", "B"], 4624))
        self.assertIsNone(eventids.describe(None, 4624))

    def test_a_level_that_only_looks_like_a_digit_reads_as_written(self):
        data = build.template_log([build.template_record([
            (0x06, struct.pack("<H", 4624)),
            (0x01, "\u00b2".encode("utf-16-le")),        # superscript two
            (0x11, struct.pack("<Q", build.filetime(2024, 3, 1, 10, 0)))])])
        r = evtx.parse(data)
        self.assertEqual(r["records"][0]["level"], "\u00b2")

    def test_a_log_over_the_read_limit_says_records_are_missing(self):
        old = evtx.LOG_READ_MAX
        evtx.LOG_READ_MAX = 4096 + 65536          # header and one chunk
        self.addCleanup(setattr, evtx, "LOG_READ_MAX", old)
        good = build.template_log([self.normal()])
        r = evtx.sweep([
            ("Big.evtx", "/Big.evtx", lambda: good, 5 * evtx.LOG_READ_MAX),
            ("Small.evtx", "/Small.evtx", lambda: good, 900)])
        big, small = r["logs"]
        self.assertTrue(big["partial"])
        self.assertTrue(any("only the first %d" % evtx.LOG_READ_MAX in f
                            for f in big["findings"]))
        self.assertFalse(small.get("partial"))
        self.assertEqual(small["findings"], [])



class DeletedLogs(unittest.TestCase):
    """A log that is a deleted file may since have had its clusters reused;
    its events are marked, not silently merged among the live ones."""

    def test_events_from_a_deleted_log_are_marked_and_live_ones_are_not(self):
        live = security_log()
        gone = build.build_log([build.event(
            4624, SEC, "2024-03-01T12:00:00.000Z",
            data={"LogonType": 2, "TargetUserName": "carol"})])
        r = evtx.sweep([
            ("Security.evtx", "/Logs/Security.evtx", lambda: live, None, False),
            ("Old.evtx", "/Logs/Old.evtx", lambda: gone, None, True)])
        live_row, gone_row = r["logs"]
        self.assertFalse(live_row["deleted"])
        self.assertTrue(gone_row["deleted"])
        by_log = {}
        for e in r["events"]:
            by_log.setdefault(e["log"], set()).add(e["deleted"])
        self.assertEqual(by_log, {0: {False}, 1: {True}})

    def test_a_deleted_log_that_no_longer_parses_says_it_is_deleted(self):
        r = evtx.sweep([("Security.evtx", "/Logs/Security.evtx",
                         lambda: b"PK\x03\x04" * 50, 200, True)])
        row = r["logs"][0]
        self.assertTrue(row["deleted"])
        self.assertIn("not an event log", row["error"])

    def test_logs_without_the_flag_are_live(self):
        r = evtx.sweep([("A.evtx", "/A.evtx", security_log)])
        self.assertFalse(r["logs"][0]["deleted"])
        self.assertTrue(all(e["deleted"] is False for e in r["events"]))


class Cancelled(Exception):
    """Stands in for the server's TaskCancelled, an ordinary Exception."""


class CountingReader:
    def __init__(self, data):
        self.data = data
        self.size = len(data)
        self.chunk_reads = 0
        self.largest = 0

    def read_at(self, offset, length):
        if length >= evtx.CHUNK_SIZE:
            self.chunk_reads += 1
        self.largest = max(self.largest, length)
        return self.data[offset:offset + length]


PER_CHUNK = 60


def big_log(chunks=40, per_chunk=PER_CHUNK):
    groups = []
    for c in range(chunks):
        groups.append([
            build.event(4624 + (i % 5), SEC,
                        "2024-03-%02dT%02d:%02d:00.000Z" % (
                            1 + c % 28, i % 24, i % 60),
                        data={"LogonType": 3, "TargetUserName": "u%d" % i})
            for i in range(per_chunk)])
    return build.build_log_chunks(groups)


class Streaming(unittest.TestCase):
    """A sweep reads a log a chunk at a time: memory does not grow with the
    log, and cancelling takes effect within a chunk."""

    @classmethod
    def setUpClass(cls):
        cls.data = big_log()

    def test_a_chunk_at_a_time_reads_the_same_records_as_parse(self):
        whole = evtx.parse(self.data)["records"]
        scan = evtx.LogScan(CountingReader(self.data).read_at,
                            len(self.data))
        self.assertTrue(scan.valid)
        streamed = list(scan.records())
        self.assertEqual(len(streamed), len(whole))
        self.assertEqual(
            [(r["record_id"], r["event_id"], r["provider"], r["created"],
              r["description"]) for r in streamed],
            [(r["record_id"], r["event_id"], r["provider"], r["created"],
              r["description"]) for r in whole])
        self.assertTrue(all("fields" not in r for r in streamed))
        self.assertEqual(scan.chunks, 40)

    def test_memory_does_not_grow_with_the_log(self):
        import tracemalloc
        reader = CountingReader(self.data)
        tracemalloc.start()
        r = evtx.sweep([("Big.evtx", "/Big.evtx", reader, len(self.data),
                         False)], max_events=50)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertEqual(r["total_events"], 40 * PER_CHUNK)
        self.assertEqual(len(r["events"]), 50)
        self.assertEqual(reader.chunk_reads, 40)
        self.assertLessEqual(reader.largest, evtx.CHUNK_SIZE)
        # The log is ~2.6 MB; a chunk and fifty events are far below that,
        # where reading and parsing the whole thing was well above it.
        self.assertLess(peak, len(self.data) // 4)
        tracemalloc.start()
        evtx.parse(self.data)
        _, whole_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertGreater(whole_peak, peak * 4)

    def test_the_newest_events_are_kept_and_in_order(self):
        r = evtx.sweep([("Big.evtx", "/Big.evtx", CountingReader(self.data))],
                       max_events=25)
        times = [e["time"] for e in r["events"]]
        self.assertEqual(times, sorted(times))
        everything = evtx.sweep([("Big.evtx", "/Big.evtx",
                                  CountingReader(self.data))],
                                max_events=10 ** 6)["events"]
        self.assertEqual([e["record_id"] for e in r["events"]],
                         [e["record_id"] for e in everything[-25:]])
        self.assertEqual(r["total_events"], len(everything))
        self.assertTrue(r["truncated"])

    def test_a_cancel_between_chunks_stops_the_reading_promptly(self):
        reader = CountingReader(self.data)
        calls = []

        def progress(p):
            calls.append(p)
            if len(calls) == 6:
                raise Cancelled()

        with self.assertRaises(Cancelled):
            evtx.sweep([("Big.evtx", "/Big.evtx", reader)],
                       progress=progress)
        self.assertLessEqual(reader.chunk_reads, 6)
        self.assertLess(reader.chunk_reads, 40)

    def test_progress_advances_with_the_chunks_and_ends_at_one(self):
        calls = []
        evtx.sweep([("Big.evtx", "/Big.evtx", CountingReader(self.data))],
                   progress=calls.append)
        self.assertGreater(len(calls), 30)
        self.assertEqual(calls[-1], 1.0)
        self.assertTrue(all(0 <= a <= 1 for a in calls))
        self.assertEqual(calls, sorted(calls))

    def test_a_log_that_fails_partway_keeps_what_was_read(self):
        data = bytearray(self.data)
        # Damage the third chunk's magic: reading stops there, quietly (a
        # damaged chunk ends a log, as it does for parse()).
        third = 4096 + 2 * evtx.CHUNK_SIZE
        data[third:third + 8] = b"XXXXXXXX"
        r = evtx.sweep([("Big.evtx", "/Big.evtx",
                         CountingReader(bytes(data)))])
        self.assertEqual(r["logs"][0]["records"], 2 * PER_CHUNK)
        self.assertNotIn("error", r["logs"][0])


class SweepRoute(unittest.TestCase):
    """The volume-wide route passes each entry's deleted flag through."""

    def test_the_route_marks_deleted_entries(self):
        import http.client
        import json
        import shutil
        import socket
        import tempfile
        import threading
        import time
        from unittest import mock
        import imagebuild_fat
        from engine import server

        d = tempfile.mkdtemp(prefix="strata-evtx-route-")
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        img = os.path.join(d, "disk.img")
        with open(img, "wb") as fh:
            fh.write(imagebuild_fat.build_fat(16))
        logs = {"Security.evtx": security_log(), "Old.evtx": system_log()}

        class Fs:
            name = "FAT"
            root_node = 0

            def listdir(self, node, path):
                return [{"name": n, "path": "/" + n, "is_dir": False,
                         "size": len(b), "start_cluster": i + 2,
                         "deleted": n == "Old.evtx"}
                        for i, (n, b) in enumerate(sorted(logs.items()))]

            def read_file(self, entry, max_bytes=None):
                return logs[entry["name"]][:max_bytes]

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
            data = r.read()
            if r.getheader("Set-Cookie"):
                cookie[:] = [r.getheader("Set-Cookie").split(";")[0]]
            c.close()
            if "json" in (r.getheader("Content-Type") or ""):
                return json.loads(data)
            return None

        call("GET", "/")
        with mock.patch.object(server.Session, "fs",
                               lambda self, part, **kw: Fs()):
            opened = call("POST", "/api/open", {
                "path": img, "case_path": os.path.join(d, "case"),
                "examiner": "T"})
            self.assertTrue(opened["open"], opened)
            task = call("POST", "/api/evtx", {"part": 0})
            for _ in range(200):
                t = call("GET", "/api/task?id=" + task["id"])
                if t.get("state") != "running":
                    break
                time.sleep(0.05)
        self.assertEqual(t["state"], "done", t)
        rows = {r["name"]: r for r in t["result"]["logs"]}
        self.assertFalse(rows["Security.evtx"]["deleted"])
        self.assertTrue(rows["Old.evtx"]["deleted"])
        self.assertEqual(
            {e["deleted"] for e in t["result"]["events"]
             if e["log"] == [r["name"] for r in t["result"]["logs"]]
             .index("Old.evtx")}, {True})


if __name__ == "__main__":
    unittest.main()
