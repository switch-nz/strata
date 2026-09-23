"""The timeline file (engine.timeline).

Paths and names are stored once per file rather than on every event. A
timeline written that way has to read back exactly as one written the old
way -- the same rows, in the same order, page for page -- and a timeline
file written before the change has to stay readable.
"""

import json
import os
import random
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import timeline                                       # noqa: E402

LEGACY_SCHEMA = """
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    sort REAL NOT NULL, time TEXT NOT NULL,
    action TEXT NOT NULL, source TEXT NOT NULL,
    name TEXT, path TEXT NOT NULL,
    is_dir INTEGER NOT NULL, deleted INTEGER NOT NULL, size INTEGER,
    node TEXT, offset INTEGER, flagged INTEGER NOT NULL,
    ev INTEGER, exhibit TEXT, part INTEGER, tags TEXT,
    partial INTEGER NOT NULL);
CREATE TABLE flags (
    ev INTEGER, part INTEGER, node TEXT, path TEXT, name TEXT,
    offset INTEGER, observations TEXT NOT NULL,
    created TEXT, fn_created TEXT, modified TEXT, fn_modified TEXT);
"""

ACTIONS = [("created", "standard"), ("modified", "standard"),
           ("accessed", "standard"), ("MFT record changed", "$FILE_NAME"),
           ("modified", "$FILE_NAME")]


def iso(t):
    return "2024-03-%02dT%02d:%02d:%02dZ" % (
        1 + t // 86400, t // 3600 % 24, t // 60 % 60, t % 60)


def make_batches(seed=7):
    rnd = random.Random(seed)
    batches = []
    for b in range(3):
        events, flags = [], []
        for i in range(400):
            path = "/dir%d/%s/file-%03d.txt" % (rnd.randrange(5),
                                                rnd.choice("zyxba"), i)
            name = path.rsplit("/", 1)[1]
            # Plenty of events at the same instant, so ties are decided by
            # path, then action, then insertion order.
            t = 1000 + rnd.randrange(300) * 60 + rnd.choice((0, 0, 0, 17))
            flagged = rnd.random() < 0.2
            for action, source in rnd.sample(ACTIONS, 3):
                events.append({
                    "sort": float(t), "time": iso(t), "action": action,
                    "source": source,
                    # Occasionally an event names the file differently.
                    "name": name if rnd.random() > 0.02 else "ALT-" + name,
                    "path": path, "is_dir": False,
                    "deleted": rnd.random() < 0.1, "size": i * 10,
                    "node": i + 100 * b, "offset": i * 4096,
                    "flagged": flagged})
            if flagged:
                flags.append({
                    "path": path, "name": name, "node": i + 100 * b,
                    "offset": i * 4096,
                    "observations": [{"kind": "si_before_fn",
                                      "severity": "high"}],
                    "created": iso(t), "fn_created": iso(t + 5),
                    "modified": iso(t), "fn_modified": iso(t + 5)})
        batches.append({"events": events, "flags": flags, "ev": b + 1,
                        "exhibit": "Exhibit %d" % (b % 2),
                        "part": 1048576 * (b + 1),
                        "tags": "Relevant" if b == 2 else None,
                        "partial": b == 1})
    return batches


def write_new(path, batches):
    w = timeline.Writer(path)
    for b in batches:
        w.add_events(b["events"], ev=b["ev"], exhibit=b["exhibit"],
                     part=b["part"], tags=b["tags"], partial=b["partial"])
        for f in b["flags"]:
            w.add_flag(f, ev=b["ev"], part=b["part"])
    return w.finish({"kind": "test"})


def write_legacy(path, batches):
    # A timeline as the writer produced it before paths were stored once.
    db = sqlite3.connect(path)
    db.executescript(LEGACY_SCHEMA)
    minutes = {}
    for b in batches:
        for e in b["events"]:
            db.execute(
                "INSERT INTO events (sort,time,action,source,name,path,is_dir,"
                "deleted,size,node,offset,flagged,ev,exhibit,part,tags,"
                "partial) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (e["sort"], e["time"], e["action"], e["source"], e["name"],
                 e["path"], int(e["is_dir"]), int(e["deleted"]), e["size"],
                 str(e["node"]), e["offset"], int(e["flagged"]), b["ev"],
                 b["exhibit"], b["part"], b["tags"], int(b["partial"])))
            got = minutes.setdefault(int(e["sort"] // 60), [0, 0])
            got[0] += 1
            got[1] += int(e["flagged"])
        for f in b["flags"]:
            db.execute(
                "INSERT INTO flags VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (b["ev"], b["part"], str(f["node"]), f["path"], f["name"],
                 f["offset"], json.dumps(f["observations"]), f["created"],
                 f["fn_created"], f["modified"], f["fn_modified"]))
    db.execute("CREATE INDEX events_order ON events(sort, path, action)")
    db.execute("CREATE INDEX flags_item ON flags(ev, part, node)")
    db.execute(timeline._BUCKETS_TABLE % "buckets")
    db.executemany("INSERT INTO buckets VALUES (?,?,?)",
                   ((m, c[0], c[1]) for m, c in minutes.items()))
    db.execute("INSERT INTO meta VALUES ('summary', '{}')")
    db.commit()
    db.close()


def every_page(path, limit=97, **kw):
    rows, cursor = [], None
    while True:
        got = timeline.page(path, cursor=cursor, limit=limit, **kw)
        rows += got["rows"]
        if got["done"]:
            return rows
        cursor = json.loads(json.dumps(got["cursor"]))


class Store(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.batches = make_batches()
        self.new = os.path.join(self.tmp, "new.sqlite")
        self.old = os.path.join(self.tmp, "old.sqlite")
        self.summary = write_new(self.new, self.batches)
        write_legacy(self.old, self.batches)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_every_page_matches_the_old_layout(self):
        new, old = every_page(self.new), every_page(self.old)
        self.assertEqual(len(new), 3600)
        self.assertEqual(new, old)

    def test_the_order_is_time_then_path_then_action_then_insertion(self):
        rows = every_page(self.new)
        keys = [(r["sort"], r["path"], r["action"], r["id"]) for r in rows]
        self.assertEqual(keys, sorted(keys))

    def test_filters_match_the_old_layout(self):
        for kw in ({"q": "dir3"}, {"q": "ALT-"}, {"q": "file-01"},
                   {"flagged": True}, {"start": 5000, "end": 12000},
                   {"q": "z/", "flagged": True, "start": 2000}):
            new = timeline.page(self.new, limit=2000, **kw)
            old = timeline.page(self.old, limit=2000, **kw)
            self.assertEqual(new["matched"], old["matched"], kw)
            self.assertEqual(every_page(self.new, **kw),
                             every_page(self.old, **kw), kw)

    def test_rows_carry_the_same_fields_as_before(self):
        row = timeline.page(self.new, limit=1)["rows"][0]
        self.assertEqual(set(row), {
            "id", "sort", "time", "action", "source", "name", "path",
            "is_dir", "deleted", "size", "node", "offset", "flagged", "ev",
            "exhibit", "part", "tags", "partial"})

    def test_histograms_match_the_old_layout(self):
        for kw in ({}, {"flagged": True}, {"q": "dir1"},
                   {"start": 3000, "end": 9000}, {"bins": 7},
                   {"start": 3000, "end": 3600, "bins": 50}):
            self.assertEqual(timeline.histogram(self.new, **kw),
                             timeline.histogram(self.old, **kw), kw)

    def test_observations_match_the_old_layout(self):
        f = self.batches[0]["flags"][0]
        args = (1, self.batches[0]["part"], str(f["node"]))
        got = timeline.observations(self.new, *args)
        self.assertEqual(got, timeline.observations(self.old, *args))
        self.assertEqual(got["path"], f["path"])
        self.assertEqual(got["observations"][0]["kind"], "si_before_fn")

    def test_summary_counts_and_span(self):
        self.assertEqual(self.summary["count"], 3600)
        rows = every_page(self.new)
        self.assertEqual(self.summary["span"],
                         {"first": rows[0]["time"], "last": rows[-1]["time"]})
        self.assertEqual(timeline.summary(self.new)["count"], 3600)

    def test_each_path_is_stored_once(self):
        db = sqlite3.connect(self.new)
        try:
            files = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            distinct = len({e["path"] for b in self.batches
                            for e in b["events"]})
            self.assertEqual(files, distinct)
            self.assertIsNone(db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='events' "
                "AND type='table'").fetchone())
        finally:
            db.close()

    def test_nothing_is_left_beside_the_finished_file(self):
        self.assertEqual(sorted(os.listdir(self.tmp)),
                         ["new.sqlite", "old.sqlite"])

    def test_an_abandoned_build_leaves_nothing_behind(self):
        w = timeline.Writer(os.path.join(self.tmp, "gone.sqlite"))
        w.add_events(self.batches[0]["events"][:10])
        w.abandon()
        self.assertEqual(sorted(os.listdir(self.tmp)),
                         ["new.sqlite", "old.sqlite"])

    def test_an_empty_timeline(self):
        path = os.path.join(self.tmp, "empty.sqlite")
        out = timeline.Writer(path).finish({})
        self.assertEqual(out["count"], 0)
        self.assertIsNone(out["span"])
        self.assertEqual(timeline.page(path)["rows"], [])


if __name__ == "__main__":
    unittest.main()
