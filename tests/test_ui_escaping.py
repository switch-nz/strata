"""Text that comes from evidence, a case file or the examiner's disk must not
be able to run as script in the interface.

Two layers are checked. The places that were found writing such text into the
page unescaped now escape it, and the interface's own pages are served with a
Content-Security-Policy that runs only the interface's own script files, so a
place that is missed later shows the text instead of running it. The second
layer depends on the page having no inline script or inline event handlers,
which is checked too."""

import html.parser
import http.client
import os
import re
import sys
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from engine import evtx, server                                # noqa: E402

WEB = os.path.join(ROOT, "web")


def _read(name):
    with open(os.path.join(WEB, name), encoding="utf-8") as fh:
        return fh.read()


class EscapedWhereItWasNot(unittest.TestCase):

    def setUp(self):
        self.js = _read("app.js")

    def test_event_id_is_text_from_the_log(self):
        # Why the interface has to escape it: the parser hands back whatever
        # the log holds, not a number.
        import datetime
        import imagebuild_evtx as build
        bad = "<img src=x onerror=alert(1)>"
        log = build.build_log([build.event(bad, "P",
                                           datetime.datetime(2024, 1, 1))])
        self.assertEqual(evtx.parse(log)["records"][0]["event_id"], bad)

    def has(self, text):
        return text in self.js

    def test_event_viewer_escapes_id_and_record_number(self):
        self.assertFalse(self.has("${x.event_id ??"))
        self.assertTrue(self.has("${esc(x.event_id ??"))
        self.assertFalse(self.has("Record ${x.record_id}"))

    def test_audit_dialog_escapes_what_the_case_file_holds(self):
        self.assertFalse(self.has('<span class="when">${e.at}</span>'))
        self.assertFalse(self.has('<span class="what">${e.action}</span>'))
        self.assertTrue(self.has('<span class="when">${esc(e.at)}</span>'))
        self.assertTrue(self.has('<span class="what">${esc(e.action)}</span>'))

    def test_no_attribute_takes_a_path_unescaped(self):
        raw = re.findall(r'data-path="\$\{(?!esc\()[^}]*\}"', self.js)
        self.assertEqual(raw, [])


class Inline(html.parser.HTMLParser):

    def __init__(self):
        html.parser.HTMLParser.__init__(self)
        self.inline_scripts = 0
        self.handlers = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and not a.get("src"):
            self._in_script = True
        self.handlers += [k for k in a if k.startswith("on")]

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline_scripts += 1

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False


class PagePolicy(unittest.TestCase):

    def test_page_has_nothing_the_policy_would_block(self):
        p = Inline()
        p.feed(_read("index.html"))
        self.assertEqual(p.inline_scripts, 0)
        self.assertEqual(p.handlers, [])
        js = _read("app.js") + _read("strings.js")
        self.assertIsNone(re.search(r"\beval\(|new Function\(", js))
        self.assertIsNone(re.search(r"<[a-z][^>`]*\son[a-z]+=", js))

    def test_policy_runs_only_the_interfaces_own_scripts(self):
        rules = dict(r.strip().split(" ", 1)
                     for r in server.CSP_APP.split(";"))
        self.assertEqual(rules["script-src"], "'self'")
        self.assertEqual(rules["object-src"], "'none'")
        self.assertEqual(rules["base-uri"], "'none'")
        self.assertEqual(rules["frame-ancestors"], "'none'")
        self.assertNotIn("unsafe", rules["default-src"])

    def test_static_pages_are_served_with_it(self):
        saved = dict(server._BOUND)
        httpd = server._Server(("127.0.0.1", 0), server.Handler)
        port = httpd.server_address[1]
        server.set_bound_address("127.0.0.1", port)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            for path in ("/", "/app.js"):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("GET", path)
                resp = conn.getresponse()
                resp.read()
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.getheader("Content-Security-Policy"),
                                 server.CSP_APP)
                self.assertEqual(resp.getheader("X-Content-Type-Options"),
                                 "nosniff")
                conn.close()
        finally:
            httpd.shutdown()
            httpd.server_close()
            server._BOUND.update(saved)


if __name__ == "__main__":
    unittest.main()
