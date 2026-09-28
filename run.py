#!/usr/bin/env python3
"""Strata: an offline forensic image examiner.

Starts the local engine and serves the interface over HTTP."""

import argparse
import os
import sys
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.server import serve

def browser_url(host, port):
    # A wildcard bind is not an address a browser can open; loopback reaches
    # it on this machine and is one of the hosts the server accepts.
    if host in ("", "0.0.0.0"):
        host = "127.0.0.1"
    elif host in ("::", "[::]"):
        host = "::1"
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    return "http://%s:%d" % (host, port)

def open_browser(host, port):
    try:
        webbrowser.open(browser_url(host, port))
    except Exception:
        pass

def main():
    ap = argparse.ArgumentParser(prog="strata", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", nargs="?",
                    help="evidence to open at start: E01/L01, raw or split "
                         "raw, VMDK, VHD/VHDX or AD1")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8722)
    ap.add_argument("--examiner", default=os.environ.get("STRATA_EXAMINER"),
                    help="recorded against every action in the audit log")
    ap.add_argument("--browser", action="store_true",
                    help="open a browser at the UI once the server is up")
    ap.add_argument("--no-browser", action="store_true",
                    help=argparse.SUPPRESS)
    ap.add_argument("--read-only", action="store_true",
                    help="refuse export and report writing for this run")
    args = ap.parse_args()

    if args.image and not os.path.isfile(args.image):
        sys.exit("No such file: %s" % args.image)

    ready = open_browser if args.browser and not args.no_browser else None
    serve(args.host, args.port, args.image, args.examiner,
          read_only=args.read_only, on_ready=ready)

if __name__ == "__main__":
    main()
