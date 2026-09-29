"""The notes routes through the real HTTP server: they work in a case with
no exhibit loaded, and refuse to act on a note id from another case."""

import http.client
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import server                                        # noqa: E402

_PORT = []


def _port():
    if not _PORT:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        ready = threading.Event()
        threading.Thread(target=server.serve, daemon=True,
                         kwargs={"host": "127.0.0.1", "port": port,
                                 "on_ready": lambda h, p: ready.set()}).start()
        ready.wait(10)
        _PORT.append(port)
    return _PORT[0]


class Client:
    def __init__(self):
        self.port = _port()
        self.cookie = None

    def call(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        host = "127.0.0.1:%d" % self.port
        h = {"Content-Type": "application/json", "Host": host,
             "Origin": "http://" + host}
        if self.cookie:
            h["Cookie"] = self.cookie
        c.request(method, path,
                  body=json.dumps(body) if body is not None else None,
                  headers=h)
        r = c.getresponse()
        data = r.read()
        set_cookie = r.getheader("Set-Cookie")
        if set_cookie:
            self.cookie = set_cookie.split(";")[0]
        c.close()
        if "json" not in (r.getheader("Content-Type") or ""):
            return r.status, None
        return r.status, json.loads(data or b"null")


class NotesApi(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-notes-api-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.c = Client()
        self.c.call("GET", "/")

    def new_case(self, name):
        path = os.path.join(self.dir, name)
        status, _ = self.c.call("POST", "/api/case/new",
                                {"path": path, "name": name,
                                 "examiner": "Alice"})
        self.assertEqual(status, 200)
        # The page sends back the case path the notes were read from.
        status, r = self.c.call("GET", "/api/notes")
        self.assertEqual(status, 200, r)
        return r["case"]

    def test_notes_work_in_a_case_with_no_exhibit(self):
        case = self.new_case("empty")
        status, r = self.c.call("POST", "/api/note",
                                {"body": "Intake: 2 drives", "case": case})
        self.assertEqual(status, 200, r)
        status, r = self.c.call("GET", "/api/notes")
        self.assertEqual(status, 200)
        self.assertEqual([n["body"] for n in r["notes"]], ["Intake: 2 drives"])
        self.assertEqual(r["case"], case)

    def test_a_note_id_from_another_case_is_not_acted_on(self):
        a = self.new_case("a")
        self.c.call("POST", "/api/note", {"body": "note in A", "case": a})
        b = self.new_case("b")
        _, r = self.c.call("POST", "/api/note", {"body": "note in B",
                                                 "case": b})
        nid = r["id"]
        # A page still showing case A's notes tries to withdraw its note.
        status, r = self.c.call("POST", "/api/note/retract",
                                {"id": nid, "case": a})
        self.assertEqual(status, 409)
        self.assertEqual([n["body"] for n in r["notes"]], ["note in B"])
        status, r = self.c.call("POST", "/api/note/edit",
                                {"id": nid, "body": "x", "case": a})
        self.assertEqual(status, 409)
        # And a request naming no case at all is refused too.
        status, _ = self.c.call("POST", "/api/note/retract", {"id": nid})
        self.assertEqual(status, 409)
        _, r = self.c.call("GET", "/api/notes")
        self.assertEqual([n["body"] for n in r["notes"]], ["note in B"])


if __name__ == "__main__":
    unittest.main()
