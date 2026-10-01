"""Recent cases follow the examiner: setting a name after a case is open must
leave that case in the named examiner's recent list."""

import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import server                                         # noqa: E402


class RecentsFollowTheName(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-recents-test-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        old = os.environ.get("STRATA_CONFIG_DIR")
        os.environ["STRATA_CONFIG_DIR"] = os.path.join(self.dir, "cfg")

        def restore():
            if old is None:
                os.environ.pop("STRATA_CONFIG_DIR", None)
            else:
                os.environ["STRATA_CONFIG_DIR"] = old
        self.addCleanup(restore)
        self.httpd = server._Server(("127.0.0.1", 0), server.Handler)
        server.set_bound_address("127.0.0.1", self.httpd.server_port)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.cookie = None

    def call(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port)
        headers = {"Content-Type": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        conn.request(method, path, json.dumps(body) if body is not None else None,
                     headers)
        resp = conn.getresponse()
        got = resp.getheader("Set-Cookie")
        if got:
            self.cookie = got.split(";")[0]
        data = json.loads(resp.read() or b"{}")
        conn.close()
        return data

    def names(self):
        return [c["name"] for c in self.call("GET", "/api/case/recent")["cases"]]

    def test_naming_the_examiner_keeps_the_open_case_in_their_recents(self):
        self.call("GET", "/api/whoami")
        made = self.call("POST", "/api/case/new",
                         {"path": os.path.join(self.dir, "first.strata")})
        self.assertIn("case", made)
        self.assertEqual(self.names(), ["first"])
        self.call("POST", "/api/whoami", {"name": "Carol"})
        self.assertEqual(self.names(), ["first"])


if __name__ == "__main__":
    unittest.main()
