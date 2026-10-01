import os
import subprocess
import sys

from .text import t as _t

TIMEOUT = 300

IMAGE_TYPES = [
    ("Evidence images", "*.E01 *.Ex01 *.L01 *.dd *.raw *.img *.001 *.bin "
                        "*.vhdx *.avhdx *.vmdk *.vhd *.vdi *.qcow2 *.ad1 *.aff "
                        "*.aff4"),
    ("EnCase / EWF", "*.E01 *.Ex01 *.L01"),
    ("Raw", "*.dd *.raw *.img *.001 *.bin"),
    ("Virtual disks", "*.vhdx *.avhdx *.vmdk *.vhd *.vdi *.qcow2"),
    ("All files", "*"),
]
CASE_TYPES = [("Strata case", "*.strata"), ("All files", "*")]

ANY_TYPES = [("All files", "*")]

def _has_display():
    if sys.platform in ("win32", "darwin"):
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))

def available():
    if not _has_display():
        return False, ("The engine is running without a desktop session, so it "
                       "has no screen to put a file dialog on.")
    try:
        import tkinter
        import tkinter.filedialog
    except Exception:
        return False, ("This Python has no tkinter, which is what the system "
                       "file dialog is built on. On Linux it is usually a "
                       "separate package (python3-tk).")
    return True, ""

def ask(mode, title="", initial_dir="", initial_file="", kind="image"):
    ok, why = available()
    if not ok:
        raise RuntimeError(why)

    argv = [sys.executable, "-m", "engine.nativedialog",
            "--mode", mode, "--kind", kind, "--title", title or "",
            "--dir", initial_dir or "", "--file", initial_file or ""]
    try:
        r = subprocess.run(argv, capture_output=True, timeout=TIMEOUT,
                           cwd=os.path.dirname(os.path.dirname(
                               os.path.abspath(__file__))))
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            _t("nativedialog.file_dialog_open_d") % TIMEOUT)
    if r.returncode != 0:
        detail = (r.stderr or b"").decode("utf-8", "replace").strip()
        raise RuntimeError(
            _t("nativedialog.dialog_could_not_open")
            + (" " + detail.splitlines()[-1] if detail else ""))
    return (r.stdout or b"").decode("utf-8", "replace").strip()

def _child():
    import argparse
    import tkinter as tk
    from tkinter import filedialog

    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("open", "save", "dir"), required=True)
    ap.add_argument("--kind", default="image")
    ap.add_argument("--title", default="")
    ap.add_argument("--dir", default="")
    ap.add_argument("--file", default="")
    a = ap.parse_args()

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    types = {"case": CASE_TYPES, "any": ANY_TYPES}.get(a.kind, IMAGE_TYPES)
    common = {"title": a.title or "Choose a file",
              "initialdir": a.dir or os.path.expanduser("~")}
    if a.mode == "dir":
        path = filedialog.askdirectory(title=a.title or "Choose a folder",
                                       initialdir=common["initialdir"])
    elif a.mode == "save":
        path = filedialog.asksaveasfilename(
            initialfile=a.file or "", filetypes=types, **common)
    else:
        path = filedialog.askopenfilename(filetypes=types, **common)

    root.destroy()
    if path:
        sys.stdout.write(str(path))
    return 0

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.exit(_child())
