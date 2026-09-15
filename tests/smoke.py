#!/usr/bin/env python3
"""CI smoke test: launch the real server and exercise it over HTTP.

Uses only the standard library. Run directly:

    python3 tests/smoke.py
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_ready(port, proc, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(
                "smoke: server exited early with code %s" % proc.returncode)
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/api/version" % port, timeout=2):
                return
        except urllib.error.HTTPError:
            return                       # answered, even with an error code
        except OSError:
            time.sleep(0.2)
    raise SystemExit("smoke: server not ready after %.0fs" % timeout)


def get(port, path):
    with urllib.request.urlopen(
            "http://127.0.0.1:%d%s" % (port, path), timeout=10) as r:
        return r.status, r.read()


def post(port, path, body):
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (port, path),
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def main():
    config_dir = tempfile.mkdtemp(prefix="strata-smoke-")
    env = dict(os.environ, STRATA_CONFIG_DIR=config_dir)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "run.py", "--port", str(port), "--no-browser"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    failures = []
    try:
        wait_ready(port, proc)

        # 1. version endpoint answers
        status, body = get(port, "/api/version")
        doc = json.loads(body)
        if status != 200 or not doc.get("version"):
            failures.append("/api/version: %s %r" % (status, body[:120]))

        # 2. static app shell and core assets served
        status, body = get(port, "/")
        if status != 200 or b"id=\"btn-theme\"" not in body:
            failures.append("GET /: status=%s shell bytes missing" % status)
        for asset in ("/app.js", "/style.css"):
            status, _ = get(port, asset)
            if status != 200:
                failures.append("GET %s: status=%s" % (asset, status))

        # 3. prefs whitelist: valid value stored, bogus dropped
        status, doc = post(port, "/api/prefs",
                           {"examiner": "smoke", "theme": "sepia"})
        if doc.get("prefs", {}).get("theme") != "sepia":
            failures.append("valid theme not stored: %r" % doc.get("prefs"))
        status, doc = post(port, "/api/prefs",
                           {"examiner": "smoke", "theme": "bogus"})
        if doc.get("prefs", {}).get("theme") == "bogus":
            failures.append("bogus theme accepted: %r" % doc.get("prefs"))
        status, body = get(port, "/api/prefs?examiner=smoke")
        doc = json.loads(body)
        if doc.get("prefs", {}).get("theme") != "sepia":
            failures.append("stored theme lost on read: %r" % doc.get("prefs"))

        # 4. prefs persisted to disk
        prefs_file = os.path.join(config_dir, "prefs.json")
        with open(prefs_file, encoding="utf-8") as fh:
            on_disk = json.load(fh)
        if on_disk.get("smoke", {}).get("theme") != "sepia":
            failures.append("prefs.json missing smoke theme: %r" % on_disk)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            failures.append("server did not exit on SIGTERM")
        shutil.rmtree(config_dir, ignore_errors=True)

    if failures:
        for f in failures:
            print("smoke FAIL:", f)
        raise SystemExit(1)
    print("smoke: ok (port %d)" % port)


if __name__ == "__main__":
    main()