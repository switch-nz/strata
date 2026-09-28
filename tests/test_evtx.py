"""Windows event logs (engine.evtx): records decode with descriptions from
the bundled table, and a volume's logs merge into one timeline."""

import os
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


if __name__ == "__main__":
    unittest.main()
