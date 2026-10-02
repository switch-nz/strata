import struct

from .nodes import node_of

SIGNATURES = [
    (0, b"\xFF\xD8\xFF", "jpeg"),
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    (0, b"GIF87a", "gif"),
    (0, b"GIF89a", "gif"),
    (0, b"BM", "bmp"),
    (0, b"II*\x00", "tiff"),
    (0, b"MM\x00*", "tiff"),
    (0, b"\x00\x00\x01\x00", "ico"),
    (0, b"8BPS", "psd"),
    (0, b"%PDF-", "pdf"),
    (0, b"{\\rtf", "rtf"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),
    (0, b"PK\x03\x04", "zip"),
    (0, b"PK\x05\x06", "zip"),
    (0, b"PK\x07\x08", "zip"),
    (0, b"\x1f\x8b\x08", "gzip"),
    (0, b"BZh", "bzip2"),
    (0, b"Rar!\x1a\x07", "rar"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"\x04\x22\x4d\x18", "lz4"),
    (0, b"\x28\xb5\x2f\xfd", "zstd"),
    (0, b"MSCF", "cab"),
    (0, b"MZ", "pe"),
    (0, b"\x7fELF", "elf"),
    (0, b"\xca\xfe\xba\xbe", "class"),
    (0, b"\xce\xfa\xed\xfe", "macho"),
    (0, b"\xcf\xfa\xed\xfe", "macho"),
    (0, b"SQLite format 3\x00", "sqlite"),
    (4, b"\xef\xcd\xab\x89", "esedb"),
    (0, b"regf", "regf"),
    (0, b"ElfFile\x00", "evtx"),
    (0, b"MAM\x04", "mam"),
    (4, b"SCCA", "prefetch"),
    (0, b"ID3", "mp3"),
    (0, b"\xff\xfb", "mp3"),
    (0, b"\xff\xf3", "mp3"),
    (0, b"OggS", "ogg"),
    (0, b"fLaC", "flac"),
    (0, b"\x1a\x45\xdf\xa3", "matroska"),
    (0, b"FLV\x01", "flv"),
    (0, b"\x30\x26\xb2\x75", "asf"),
    (0, b"%!PS", "postscript"),
    (0, b"\xed\xab\xee\xdb", "rpm"),
    (0, b"!<arch>", "ar"),
    (0, b"\xd4\xc3\xb2\xa1", "pcap"),
    (0, b"\x0a\x0d\x0d\x0a", "pcapng"),
    (0, b"\x4c\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    (0, b"AT&TFORM", "djvu"),
    (0, b"wOFF", "woff"),
    (0, b"wOF2", "woff2"),
    (0, b"\x00\x01\x00\x00\x00", "ttf"),
    (0, b"OTTO", "otf"),
    (257, b"ustar", "tar"),
]

TYPE_NAMES = {
    "jpeg": "JPEG image", "png": "PNG image", "gif": "GIF image",
    "bmp": "Bitmap image", "tiff": "TIFF image", "ico": "Icon",
    "psd": "Photoshop document", "pdf": "PDF document", "rtf": "Rich text",
    "ole2": "OLE2 compound document", "zip": "ZIP container",
    "gzip": "gzip archive", "bzip2": "bzip2 archive", "rar": "RAR archive",
    "7z": "7-Zip archive", "xz": "xz archive", "lz4": "LZ4 archive",
    "zstd": "Zstandard archive", "cab": "Cabinet archive", "tar": "tar archive",
    "pe": "Windows executable", "elf": "ELF binary", "class": "Java class",
    "macho": "Mach-O binary", "sqlite": "SQLite database",
    "esedb": "ESE database (Extensible Storage Engine)",
    "regf": "Windows registry hive", "evtx": "Windows event log",
    "prefetch": "Windows prefetch",
    "mam": "MAM-compressed data (LZXPRESS)", "mp3": "MP3 audio", "ogg": "Ogg media",
    "flac": "FLAC audio", "matroska": "Matroska video", "flv": "Flash video",
    "asf": "ASF / WMV media", "isobmff": "MP4 / QuickTime media",
    "riff": "RIFF container", "postscript": "PostScript", "rpm": "RPM package",
    "ar": "ar archive", "pcap": "packet capture", "pcapng": "packet capture",
    "lnk": "Windows shortcut", "djvu": "DjVu document", "woff": "Web font",
    "woff2": "Web font", "ttf": "TrueType font", "otf": "OpenType font",
    "text": "text", "empty": "empty",
}

EXT_TYPES = {
    "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "jpe": {"jpeg"}, "jfif": {"jpeg"},
    "png": {"png"}, "gif": {"gif"}, "bmp": {"bmp"}, "dib": {"bmp"},
    "tif": {"tiff"}, "tiff": {"tiff"}, "ico": {"ico"}, "psd": {"psd"},
    "pdf": {"pdf"}, "rtf": {"rtf", "text"},
    "doc": {"ole2"}, "xls": {"ole2"}, "ppt": {"ole2"}, "msg": {"ole2"},
    "vsd": {"ole2"}, "pub": {"ole2"},
    "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"}, "docm": {"zip"},
    "xlsm": {"zip"}, "pptm": {"zip"}, "odt": {"zip"}, "ods": {"zip"},
    "odp": {"zip"}, "epub": {"zip"}, "jar": {"zip"}, "apk": {"zip"},
    "war": {"zip"}, "xpi": {"zip"}, "vsix": {"zip"}, "zip": {"zip"},
    "gz": {"gzip"}, "tgz": {"gzip"}, "bz2": {"bzip2"}, "rar": {"rar"},
    "7z": {"7z"}, "xz": {"xz"}, "zst": {"zstd"}, "lz4": {"lz4"},
    "cab": {"cab"}, "tar": {"tar"},
    "exe": {"pe"}, "dll": {"pe"}, "sys": {"pe"}, "ocx": {"pe"}, "scr": {"pe"},
    "cpl": {"pe"}, "msi": {"ole2"}, "so": {"elf"}, "class": {"class"},
    "dylib": {"macho"},
    "sqlite": {"sqlite"}, "sqlite3": {"sqlite"},
    "edb": {"esedb"}, "dit": {"esedb"},
    "evtx": {"evtx"},
    "pf": {"prefetch", "mam"},
    "lnk": {"lnk"},
    "mp3": {"mp3"}, "ogg": {"ogg"}, "oga": {"ogg"}, "flac": {"flac"},
    "mkv": {"matroska"}, "webm": {"matroska"}, "flv": {"flv"},
    "wmv": {"asf"}, "wma": {"asf"}, "asf": {"asf"},
    "mp4": {"isobmff"}, "m4a": {"isobmff"}, "m4v": {"isobmff"},
    "mov": {"isobmff"}, "heic": {"isobmff"}, "avif": {"isobmff"},
    "3gp": {"isobmff"},
    "wav": {"riff"}, "avi": {"riff"}, "webp": {"riff"},
    "ps": {"postscript"}, "eps": {"postscript"}, "rpm": {"rpm"},
    "pcap": {"pcap"}, "pcapng": {"pcapng"}, "djvu": {"djvu"},
    "woff": {"woff"}, "woff2": {"woff2"}, "ttf": {"ttf"}, "otf": {"otf", "ttf"},
    "txt": {"text"}, "log": {"text"}, "csv": {"text"}, "ini": {"text"},
    "cfg": {"text"}, "conf": {"text"}, "md": {"text"}, "json": {"text"},
    "xml": {"text"}, "html": {"text"}, "htm": {"text"}, "css": {"text"},
    "js": {"text"}, "py": {"text"}, "sh": {"text"}, "bat": {"text"},
    "ps1": {"text"}, "sql": {"text"}, "yml": {"text"}, "yaml": {"text"},
    "svg": {"text"}, "vbs": {"text"}, "reg": {"text"}, "eml": {"text"},
    "manifest": {"text"}, "mum": {"text"}, "inf": {"text"}, "man": {"text"},
    "cdxml": {"text"}, "resjson": {"text"}, "properties": {"text"},
    "url": {"text"}, "srt": {"text"}, "vtt": {"text"}, "toml": {"text"},
}

MATCH = "match"
MISMATCH = "mismatch"
NO_EXT = "no extension"
NO_SIG = "no signature"
UNKNOWN_EXT = "unknown extension"
UNREADABLE = "unreadable"
EMPTY = "empty"

_SORTED = sorted(SIGNATURES, key=lambda s: -len(s[1]))

def _isobmff(data):
    return len(data) >= 12 and data[4:8] == b"ftyp"

def _riff(data):
    return len(data) >= 12 and data[:4] == b"RIFF"

def detect(data):
    if not data:
        return None
    for off, magic, tid in _SORTED:
        if data[off:off + len(magic)] == magic:
            if tid == "pe" and not _pe_plausible(data):
                continue
            if tid == "bmp" and not _bmp_plausible(data):
                continue
            return tid
    if _isobmff(data):
        return "isobmff"
    if _riff(data):
        return "riff"
    return None

def _pe_plausible(data):
    if len(data) < 0x40:
        return False
    try:
        off = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return False
    if off <= 0 or off > len(data) - 4:
        return b"This program cannot be run in DOS mode" in data[:256]
    return data[off:off + 2] == b"PE"

_DIB_SIZES = {12, 16, 40, 52, 56, 64, 108, 124}

def _bmp_plausible(data):
    if len(data) < 18:
        return False
    size = struct.unpack_from("<I", data, 2)[0]
    if not 26 <= size < (1 << 31):
        return False
    if struct.unpack_from("<I", data, 6)[0] != 0:
        return False
    return struct.unpack_from("<I", data, 14)[0] in _DIB_SIZES

def looks_textual(data, sample=4096):
    if not data:
        return False
    chunk = data[:sample]
    if b"\x00\x00" in chunk[:512]:
        return False
    printable = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b < 127)
    return printable / len(chunk) > 0.92

def extension_of(name):
    base = (name or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." not in base.strip("."):
        return None
    ext = base.rsplit(".", 1)[-1].lower()
    return ext if ext and len(ext) <= 12 else None

def examine(data, name, size=None):
    ext = extension_of(name)
    claimed = EXT_TYPES.get(ext) if ext else None

    if size == 0 or (data is not None and len(data) == 0):
        return _result(ext, claimed, None, EMPTY,
                       "The file has no content to identify.")
    if data is None:
        return _result(ext, claimed, None, UNREADABLE,
                       "The file could not be read.")

    found = detect(data)
    if found is None and looks_textual(data):
        found = "text"

    if ext is None:
        return _result(ext, claimed, found, NO_EXT,
                       "No extension to check the content against.")
    if claimed is None:
        return _result(ext, claimed, found, UNKNOWN_EXT,
                       "This extension is not one with a known format, so "
                       "there is nothing to contradict.")
    if found is None:
        return _result(ext, claimed, found, NO_SIG,
                       "The content carries no recognised signature, so it "
                       "neither confirms nor contradicts the extension.")
    if found in claimed:
        return _result(ext, claimed, found, MATCH,
                       "The content is what the extension says it is.")

    hiding = found != "text" and claimed == {"text"}
    stub = found == "text" and "text" not in claimed
    severity = "low" if stub else "high"
    why = ("The extension says %s; the content is %s."
           % (" or ".join(sorted(TYPE_NAMES.get(c, c) for c in claimed)),
              TYPE_NAMES.get(found, found)))
    if hiding:
        why += (" A file given a text extension while holding a real binary "
                "format is the shape of something renamed to be overlooked.")
    elif stub:
        why += (" A binary extension holding text is usually a stub or a "
                "placeholder rather than anything concealed.")
    return _result(ext, claimed, found, MISMATCH, why, severity=severity)

def _result(ext, claimed, found, verdict, why, severity=None):
    return {
        "extension": ext,
        "extension_says": (" or ".join(sorted(TYPE_NAMES.get(c, c)
                                              for c in claimed))
                           if claimed else None),
        "detected": found,
        "content_is": TYPE_NAMES.get(found, found) if found else None,
        "verdict": verdict,
        "mismatch": verdict == MISMATCH,
        "why": why,
        "severity": severity or ("high" if verdict == MISMATCH else "info"),
    }

HEAD_BYTES = 4096

def scan(fs, entries, read=None, progress=None, limit=None):
    read = read or (lambda e, n: fs.read_file(e, n))
    counts = {}
    mismatches = []
    checked = 0
    total = max(1, len(entries))
    for i, e in enumerate(entries):
        if progress and i % 64 == 0:
            progress(i / total)
        if e.get("is_dir"):
            continue
        size = e.get("size") or 0
        data = b""
        if size:
            try:
                data = read(e, HEAD_BYTES)
            except Exception:
                data = None
        got = examine(data, e.get("name"), size=size)
        checked += 1
        counts[got["verdict"]] = counts.get(got["verdict"], 0) + 1
        if got["mismatch"]:
            mismatches.append({
                "name": e.get("name"), "path": e.get("path"),
                "size": size, "deleted": bool(e.get("deleted")),
                "modified": e.get("modified"),
                "node": node_of(e),
                **{k: got[k] for k in ("extension", "extension_says",
                                       "detected", "content_is", "why",
                                       "severity")},
            })
            if limit and len(mismatches) >= limit:
                break
    if progress:
        progress(1.0)
    return {
        "checked": checked,
        "mismatches": mismatches,
        "mismatch_count": len(mismatches),
        "census": counts,
        "note": ("A mismatch is only reported where the extension names a "
                 "definite format and the content is a definite, different "
                 "one. Files with no signature, no extension, or an extension "
                 "with no known format are counted but not accused."),
    }
