"""Start the application and check that it actually serves.

Exercises the running server rather than importing it: static assets, the
version endpoint, path-traversal refusal, and the preferences whitelist.

    python3 tests/smoke.py [-v]

Preferences are redirected to a temporary directory via STRATA_CONFIG_DIR, so
running this never touches the preferences of whoever is logged in.
"""

import http.client
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
EXAMINER = "strata-ci"
STARTUP_TIMEOUT = 60
SHUTDOWN_TIMEOUT = 15

verbose = False
failures = []


def log(msg):
    if verbose:
        print("   %s" % msg)


def check(name, fn):
    try:
        detail = fn()
    except Exception as exc:
        failures.append(name)
        print("FAIL %s" % name)
        print("     %s: %s" % (type(exc).__name__, exc))
        return False
    print("ok   %s%s" % (name, " - %s" % detail if detail else ""))
    return True


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get(opener, url, want=200):
    try:
        r = opener.open(url, timeout=20)
    except urllib.error.HTTPError as exc:
        r = exc
    body = r.read()
    if r.status != want:
        raise AssertionError("%s returned %d, expected %d" % (url, r.status, want))
    return r, body


def get_json(opener, url):
    r, body = get(opener, url)
    ctype = r.headers.get("Content-Type", "")
    if "json" not in ctype:
        raise AssertionError("%s is %r, expected JSON" % (url, ctype))
    return json.loads(body.decode("utf-8"))


def post_json(opener, url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with opener.open(req, timeout=20) as r:
        if r.status != 200:
            raise AssertionError("POST %s returned %d" % (url, r.status))
        return json.loads(r.read().decode("utf-8"))


def raw_get(port, path):
    """Send path verbatim, without the normalising urllib does."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    try:
        conn.putrequest("GET", path, skip_host=False, skip_accept_encoding=True)
        conn.endheaders()
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def wait_for_server(proc, base, log_path):
    deadline = time.time() + STARTUP_TIMEOUT
    while time.time() < deadline:
        if proc.poll() is not None:
            raise AssertionError(
                "server exited with %s before answering\n%s"
                % (proc.returncode, read_log(log_path)))
        try:
            with urllib.request.urlopen(base + "/api/version", timeout=5) as r:
                if r.status == 200:
                    return time.time()
        except Exception:
            time.sleep(0.25)
    raise AssertionError("server did not answer within %ds\n%s"
                         % (STARTUP_TIMEOUT, read_log(log_path)))


def read_log(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            out = f.read().strip()
    except OSError:
        return "(no server output)"
    return "--- server output ---\n%s" % (out or "(empty)")


def run(config_dir, log_path):
    port = free_port()
    base = "http://127.0.0.1:%d" % port

    env = dict(os.environ)
    env["STRATA_CONFIG_DIR"] = config_dir
    env["PYTHONUNBUFFERED"] = "1"

    print("starting %s run.py --port %d" % (os.path.basename(sys.executable), port))
    with open(log_path, "wb") as sink:
        proc = subprocess.Popen(
            [sys.executable, "run.py", "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env, stdout=sink, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL)

    try:
        started = time.time()
        wait_for_server(proc, base, log_path)
        print("ok   server answered after %.1fs" % (time.time() - started))

        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor())

        def version():
            d = get_json(opener, base + "/api/version")
            v = d.get("version")
            if not isinstance(v, str) or not v.strip():
                raise AssertionError("no version string in %r" % d)
            return v

        def shell():
            r, body = get(opener, base + "/")
            text = body.decode("utf-8", "replace")
            if "<title>Strata</title>" not in text:
                raise AssertionError("/ is not the app shell")
            # strings.js loads app.js itself once translations are in.
            for ref in ("style.css", "strings.js"):
                if ref not in text:
                    raise AssertionError("shell does not reference %s" % ref)
            return "%d bytes" % len(body)

        def asset(path, kinds):
            def fn():
                r, body = get(opener, base + path)
                ctype = r.headers.get("Content-Type", "")
                if not any(k in ctype for k in kinds):
                    raise AssertionError("%s served as %r" % (path, ctype))
                if not body:
                    raise AssertionError("%s is empty" % path)
                return "%s, %d bytes" % (ctype, len(body))
            return fn

        def missing():
            get(opener, base + "/no-such-asset.js", want=404)

        def traversal():
            for path in ("/../run.py", "/%2e%2e/run.py", "/..%2frun.py"):
                status, body = raw_get(port, path)
                if status == 200 and b"STRATA_EXAMINER" in body:
                    raise AssertionError("%s escaped the web root" % path)
                if status not in (400, 403, 404):
                    raise AssertionError(
                        "%s returned %d, expected a refusal" % (path, status))
            return "3 escapes refused"

        def prefs_isolated():
            d = get_json(opener, base + "/api/prefs?examiner=" + EXAMINER)
            if not isinstance(d.get("prefs"), dict):
                raise AssertionError("no prefs dict in %r" % d)
            where = os.path.abspath(d.get("path") or "")
            if not where.startswith(os.path.abspath(config_dir)):
                raise AssertionError(
                    "prefs live at %s, outside STRATA_CONFIG_DIR %s"
                    % (where, config_dir))
            return "under STRATA_CONFIG_DIR"

        def prefs_accepts():
            d = post_json(opener, base + "/api/prefs",
                          {"examiner": EXAMINER, "theme": "midnight"})
            if d["prefs"].get("theme") != "midnight":
                raise AssertionError("theme not stored: %r" % d["prefs"])
            again = get_json(opener, base + "/api/prefs?examiner=" + EXAMINER)
            if again["prefs"].get("theme") != "midnight":
                raise AssertionError("theme did not persist: %r" % again["prefs"])
            return "midnight persisted"

        def prefs_rejects():
            d = post_json(opener, base + "/api/prefs",
                          {"examiner": EXAMINER, "theme": "bogus"})
            got = d["prefs"].get("theme")
            if got == "bogus":
                raise AssertionError("whitelist accepted a bogus theme")
            if got != "midnight":
                raise AssertionError(
                    "rejection clobbered the stored value: %r" % got)
            return "bogus dropped, midnight kept"

        def prefs_clamps():
            d = post_json(opener, base + "/api/prefs",
                          {"examiner": EXAMINER, "tree_width": 99999})
            got = d["prefs"].get("tree_width")
            if got != 640:
                raise AssertionError("tree_width %r, expected clamp to 640" % got)
            return "99999 clamped to 640"

        def unknown_key():
            d = post_json(opener, base + "/api/prefs",
                          {"examiner": EXAMINER, "not_a_real_pref": "x"})
            if "not_a_real_pref" in d["prefs"]:
                raise AssertionError("unknown key was stored")
            return "unknown key dropped"

        check("/api/version reports a version", version)
        check("/ serves the app shell", shell)
        check("/app.js is served", asset("/app.js", ("javascript", "ecmascript")))
        check("/strings.js is served", asset("/strings.js", ("javascript", "ecmascript")))
        check("/style.css is served", asset("/style.css", ("css",)))
        check("a missing asset is 404", missing)
        check("path traversal is refused", traversal)
        check("prefs are isolated to STRATA_CONFIG_DIR", prefs_isolated)
        check("prefs accept a valid theme", prefs_accepts)
        check("prefs reject a bogus theme", prefs_rejects)
        check("prefs clamp an out-of-range width", prefs_clamps)
        check("prefs drop an unknown key", unknown_key)

    finally:
        code = stop(proc)

    # serve() handles KeyboardInterrupt only, so SIGTERM is not a clean exit;
    # what matters for CI is that the process goes away promptly when asked.
    check("server stops when signalled", lambda: "exit %s" % code)
    log(read_log(log_path))


def stop(proc):
    if proc.poll() is not None:
        return proc.returncode
    proc.terminate()
    try:
        proc.wait(timeout=SHUTDOWN_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=SHUTDOWN_TIMEOUT)
        failures.append("server ignored terminate")
        print("FAIL server did not stop within %ds; killed" % SHUTDOWN_TIMEOUT)
    return proc.returncode


def main():
    global verbose
    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    config_dir = tempfile.mkdtemp(prefix="strata-ci-")
    log_path = os.path.join(config_dir, "server.log")
    try:
        run(config_dir, log_path)
    except AssertionError as exc:
        failures.append("server startup")
        print("FAIL server startup")
        print("     %s" % exc)
    finally:
        shutil.rmtree(config_dir, ignore_errors=True)

    print()
    if failures:
        print("%d check(s) failed: %s" % (len(failures), ", ".join(failures)))
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
