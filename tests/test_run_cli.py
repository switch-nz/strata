import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import run
from engine import server


class BrowserUrl(unittest.TestCase):

    def test_loopback_host_is_used_as_given(self):
        self.assertEqual(run.browser_url("127.0.0.1", 8722),
                         "http://127.0.0.1:8722")
        self.assertEqual(run.browser_url("localhost", 9000),
                         "http://localhost:9000")

    def test_wildcard_binds_open_loopback(self):
        self.assertEqual(run.browser_url("0.0.0.0", 8722),
                         "http://127.0.0.1:8722")
        self.assertEqual(run.browser_url("::", 8722), "http://[::1]:8722")

    def test_ipv6_literal_is_bracketed(self):
        self.assertEqual(run.browser_url("fe80::1", 8722),
                         "http://[fe80::1]:8722")

    def test_named_host_is_kept(self):
        self.assertEqual(run.browser_url("10.0.0.5", 8722),
                         "http://10.0.0.5:8722")


class OnReady(unittest.TestCase):

    def test_on_ready_runs_once_the_port_accepts_connections(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        seen = {}
        done = threading.Event()

        def ready(host, p):
            try:
                with socket.create_connection((host, p), timeout=2):
                    seen["connected"] = True
            finally:
                seen["args"] = (host, p)
                done.set()

        t = threading.Thread(target=server.serve,
                             kwargs={"host": "127.0.0.1", "port": port,
                                     "on_ready": ready},
                             daemon=True)
        t.start()
        self.assertTrue(done.wait(10))
        self.assertEqual(seen.get("args"), ("127.0.0.1", port))
        self.assertTrue(seen.get("connected"))


if __name__ == "__main__":
    unittest.main()
