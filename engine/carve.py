import re
import struct
import zlib
from . import entropy as entropy_mod

MAX_CARVE = 128 * 1024 * 1024

PROBE = 8 << 20

CATEGORIES = ("images", "documents", "archives", "databases", "email",
              "media", "system", "executables")

BOUNDED = ("structure", "footer")

class SignatureError(ValueError):

    def __init__(self, key, *args):
        ValueError.__init__(self, key)
        self.key = key
        self.args_ = args

class Pattern:

    _TOKEN = re.compile(r'\s+|,|"([^"]*)"|\?\?|(?:0[xX])?([0-9A-Fa-f]{2})')

    def __init__(self, spec):
        if isinstance(spec, (bytes, bytearray)):
            self.items = list(bytes(spec))
        elif isinstance(spec, str):
            self.items = self._parse(spec)
        else:
            self.items = list(spec)
        self.literal = None not in self.items
        if self.literal:
            self.bytes = bytes(self.items)
            self._rx = None
        else:
            self.bytes = None
            self._rx = re.compile(b"".join(
                b"." if b is None else re.escape(bytes([b]))
                for b in self.items), re.DOTALL)

    @classmethod
    def _parse(cls, text):
        items = []
        i = 0
        while i < len(text):
            m = cls._TOKEN.match(text, i)
            if not m or m.end() == i:
                raise SignatureError("bad_byte", text[i:i + 8])
            if m.group(1) is not None:
                try:
                    items.extend(m.group(1).encode("ascii"))
                except UnicodeEncodeError:
                    raise SignatureError("not_ascii", m.group(1))
            elif m.group(0) == "??":
                items.append(None)
            elif m.group(2) is not None:
                items.append(int(m.group(2), 16))
            i = m.end()
        return items

    def __len__(self):
        return len(self.items)

    def find(self, buf, start=0):
        if self.literal:
            return buf.find(self.bytes, start)
        m = self._rx.search(buf, start)
        return m.start() if m else -1

    def rfind(self, buf, start=0):
        if self.literal:
            return buf.rfind(self.bytes, start)
        last, at = -1, start
        while True:
            got = self.find(buf, at)
            if got < 0:
                return last
            last, at = got, got + 1

    def text(self):
        return " ".join("??" if b is None else "%02X" % b for b in self.items)

class Signature:

    def __init__(self, ext, name, header, footer=None, max_size=32 * 1024 * 1024,
                 sizer=None, header_offset=0, strict=False, default_size=None,
                 category="documents", footer_last=False, footer_extra=0,
                 missing_footer=None, stop_at_allocated=True,
                 stop_at_zeros=False, custom=False):
        self.ext = ext
        self.name = name
        self.head = Pattern(header)
        self.foot = Pattern(footer) if footer else None
        self.header = self.head.bytes
        self.footer = self.foot.bytes if self.foot else None
        self.max_size = max_size
        self.sizer = sizer
        self.header_offset = header_offset
        self.strict = strict
        self.default_size = default_size or min(max_size, 1 << 20)
        self.category = category
        self.footer_last = footer_last
        self.footer_extra = footer_extra
        self.missing_footer = missing_footer or ("discard" if strict
                                                 else "estimate")
        self.stop_at_allocated = stop_at_allocated
        self.stop_at_zeros = stop_at_zeros
        self.custom = custom

def _size_png(buf):
    if len(buf) < 8:
        return None
    i = 8
    while i + 8 <= len(buf):
        length = struct.unpack(">I", buf[i:i + 4])[0]
        ctype = buf[i + 4:i + 8]
        if length > len(buf):
            return None
        i += 12 + length
        if ctype == b"IEND":
            return i
    return None

def _size_gif(buf):
    if len(buf) < 13:
        return None
    flags = buf[10]
    i = 13
    if flags & 0x80:
        i += 3 * (2 << (flags & 0x07))
    while i < len(buf):
        b = buf[i]
        if b == 0x3B:
            return i + 1
        if b == 0x21:
            i += 2
            while i < len(buf) and buf[i]:
                i += buf[i] + 1
            i += 1
        elif b == 0x2C:
            if i + 10 > len(buf):
                return None
            lf = buf[i + 9]
            i += 10
            if lf & 0x80:
                i += 3 * (2 << (lf & 0x07))
            i += 1
            while i < len(buf) and buf[i]:
                i += buf[i] + 1
            i += 1
        else:
            return None
    return None

def _size_zip(buf):
    end = buf.rfind(b"PK\x05\x06")
    if end < 0 or end + 22 > len(buf):
        return None
    comment_len = struct.unpack("<H", buf[end + 20:end + 22])[0]
    return end + 22 + comment_len

def _size_pdf(buf):
    end = buf.rfind(b"%%EOF")
    if end < 0:
        return None
    tail = buf[end + 5:end + 7]
    return end + 5 + (2 if tail.startswith(b"\r\n") else
                      1 if tail[:1] in (b"\r", b"\n") else 0)

def _size_sqlite(buf):
    if len(buf) < 32:
        return None
    page_size = struct.unpack(">H", buf[16:18])[0]
    page_size = 65536 if page_size == 1 else page_size
    page_count = struct.unpack(">I", buf[28:32])[0]
    if page_size < 512 or page_size & (page_size - 1) or not page_count:
        return None
    size = page_size * page_count
    return size if 0 < size <= len(buf) else None

def _size_bmp(buf):
    if len(buf) < 6:
        return None
    size = struct.unpack("<I", buf[2:6])[0]
    return size if 0 < size <= len(buf) else None

def _size_evtx(buf):
    if len(buf) < 48:
        return None
    chunk_count = struct.unpack("<H", buf[42:44])[0]
    size = 4096 + chunk_count * 65536
    return size if 0 < size <= len(buf) else None

def _size_pe(buf):
    if len(buf) < 0x40:
        return None
    e_lfanew = struct.unpack("<I", buf[0x3C:0x40])[0]
    if e_lfanew + 0x18 > len(buf) or buf[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    n_sections = struct.unpack("<H", buf[coff + 2:coff + 4])[0]
    opt_size = struct.unpack("<H", buf[coff + 16:coff + 18])[0]
    sec_start = coff + 20 + opt_size
    end = 0
    for i in range(n_sections):
        s = sec_start + i * 40
        if s + 40 > len(buf):
            return None
        raw_size, raw_ptr = struct.unpack("<II", buf[s + 16:s + 24])
        end = max(end, raw_ptr + raw_size)
    return end if 0 < end <= len(buf) else None

def _size_jpeg(buf):
    if len(buf) < 4:
        return None
    i = 2
    n = len(buf)
    while i + 4 <= n:
        if buf[i] != 0xFF:
            i += 1
            continue
        marker = buf[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xD9:
            return i + 2
        if marker == 0xFF:
            i += 1
            continue
        if i + 4 > n:
            break
        seg_len = struct.unpack(">H", buf[i + 2:i + 4])[0]
        if seg_len < 2:
            return None
        i += 2 + seg_len
        if marker == 0xDA:
            while i + 1 < n:
                if buf[i] == 0xFF and buf[i + 1] not in (0x00,) and \
                        not (0xD0 <= buf[i + 1] <= 0xD7):
                    break
                i += 1
    return None

def _size_regf(buf):
    if len(buf) < 0x30:
        return None
    data = struct.unpack("<I", buf[0x28:0x2C])[0]
    if not data or data % 4096:
        return None
    return 4096 + data

def _size_7z(buf):
    if len(buf) < 32:
        return None
    crc = struct.unpack("<I", buf[8:12])[0]
    if zlib.crc32(buf[12:32]) & 0xFFFFFFFF != crc:
        return None
    off, size = struct.unpack("<QQ", buf[12:28])
    total = 32 + off + size
    return total if size else None

def _size_prefetch(buf):
    if len(buf) < 16:
        return None
    size = struct.unpack("<I", buf[12:16])[0]
    return size if size >= 0x54 else None

def _size_riff(buf):
    if len(buf) < 12:
        return None
    size = struct.unpack("<I", buf[4:8])[0]
    return size + 8 + (size & 1) if size >= 4 else None

def _size_pst(buf):
    if len(buf) < 0xC0:
        return None
    ver = struct.unpack("<H", buf[10:12])[0]
    if ver in (14, 15):
        size = struct.unpack("<I", buf[0xA8:0xAC])[0]
    elif ver >= 23:
        size = struct.unpack("<Q", buf[0xB8:0xC0])[0]
    else:
        return None
    return size if size >= 0x200 else None

_BOXES = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid",
          b"meta", b"pdin", b"moof", b"mfra", b"styp", b"sidx", b"udta",
          b"pnot", b"PICT", b"prfl", b"junk"}

def _size_isobmff(buf):
    i, seen_media = 0, False
    while i + 8 <= len(buf):
        size = struct.unpack(">I", buf[i:i + 4])[0]
        kind = buf[i + 4:i + 8]
        if kind not in _BOXES:
            break
        if size == 1:
            if i + 16 > len(buf):
                return None
            size = struct.unpack(">Q", buf[i + 8:i + 16])[0]
        if size < 8:
            return None
        seen_media = seen_media or kind in (b"moov", b"mdat", b"moof", b"meta")
        i += size
    return i if seen_media and i > 8 else None

SIGNATURES = [
    Signature("jpg", "JPEG image", b"\xFF\xD8\xFF", b"\xFF\xD9",
              sizer=_size_jpeg, strict=True, category="images"),
    Signature("png", "PNG image", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82",
              sizer=_size_png, strict=True, category="images"),
    Signature("gif", "GIF image", b"GIF89a", b"\x00\x3B", sizer=_size_gif,
              strict=True, category="images"),
    Signature("gif", "GIF image", b"GIF87a", b"\x00\x3B", sizer=_size_gif,
              strict=True, category="images"),
    Signature("bmp", "Bitmap image", b"BM", sizer=_size_bmp, max_size=64 << 20,
              strict=True, category="images"),
    Signature("tif", "TIFF image", b"II*\x00", max_size=64 << 20,
              default_size=4 << 20, category="images"),
    Signature("tif", "TIFF image", b"MM\x00*", max_size=64 << 20,
              default_size=4 << 20, category="images"),
    Signature("webp", "WebP image", '"RIFF" ?? ?? ?? ?? "WEBP"',
              sizer=_size_riff, max_size=64 << 20, category="images"),
    Signature("pdf", "PDF document", b"%PDF-", b"%%EOF", sizer=_size_pdf,
              max_size=64 << 20, strict=True, category="documents"),
    Signature("doc", "OLE compound file (DOC, XLS, PPT, MSG)",
              b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", max_size=64 << 20,
              default_size=4 << 20, category="documents"),
    Signature("rtf", "Rich text", b"{\\rtf", b"}", max_size=16 << 20,
              category="documents"),
    Signature("zip", "ZIP / OOXML container", b"PK\x03\x04", sizer=_size_zip,
              max_size=64 << 20, strict=True, category="archives"),
    Signature("gz", "gzip archive", b"\x1f\x8b\x08", max_size=64 << 20,
              default_size=4 << 20, category="archives"),
    Signature("rar", "RAR archive", b"Rar!\x1a\x07", max_size=64 << 20,
              default_size=4 << 20, category="archives"),
    Signature("7z", "7-Zip archive", b"7z\xbc\xaf\x27\x1c", sizer=_size_7z,
              max_size=128 << 20, default_size=4 << 20, category="archives"),
    Signature("sqlite", "SQLite database", b"SQLite format 3\x00",
              sizer=_size_sqlite, max_size=64 << 20, strict=True,
              category="databases"),
    Signature("eml", "MIME message", b"Received: from", max_size=32 << 20,
              default_size=256 << 10, category="email"),
    Signature("pst", "Outlook data file (PST, OST)", b"!BDN", sizer=_size_pst,
              max_size=MAX_CARVE, default_size=16 << 20, category="email"),
    Signature("mp4", "MP4 / QuickTime / HEIC", b"ftyp", header_offset=4,
              sizer=_size_isobmff, max_size=MAX_CARVE, default_size=8 << 20,
              category="media"),
    Signature("wav", "WAV audio", '"RIFF" ?? ?? ?? ?? "WAVE"', sizer=_size_riff,
              max_size=MAX_CARVE, category="media"),
    Signature("avi", "AVI video", '"RIFF" ?? ?? ?? ?? "AVI "', sizer=_size_riff,
              max_size=MAX_CARVE, category="media"),
    Signature("evtx", "Windows event log", b"ElfFile\x00", sizer=_size_evtx,
              max_size=64 << 20, strict=True, category="system"),
    Signature("reg", "Registry hive", b"regf", sizer=_size_regf,
              max_size=MAX_CARVE, default_size=4 << 20, category="system"),
    Signature("lnk", "Windows shortcut",
              b"\x4c\x00\x00\x00\x01\x14\x02\x00", max_size=64 << 10,
              default_size=8 << 10, category="system"),
    Signature("pf", "Prefetch (uncompressed)", b"\x11\x00\x00\x00SCCA",
              sizer=_size_prefetch, max_size=8 << 20, default_size=256 << 10,
              category="system"),
    Signature("pf", "Prefetch (uncompressed)", b"\x17\x00\x00\x00SCCA",
              sizer=_size_prefetch, max_size=8 << 20, default_size=256 << 10,
              category="system"),
    Signature("pf", "Prefetch (uncompressed)", b"\x1a\x00\x00\x00SCCA",
              sizer=_size_prefetch, max_size=8 << 20, default_size=256 << 10,
              category="system"),
    Signature("plist", "Binary property list", b"bplist00", max_size=16 << 20,
              default_size=1 << 20, category="system"),
    Signature("exe", "PE executable", b"MZ", sizer=_size_pe, max_size=64 << 20,
              strict=True, category="executables"),
]

def catalogue():
    out, by_ext = [], {}
    for sig in SIGNATURES:
        row = by_ext.get(sig.ext)
        if row is None:
            row = by_ext[sig.ext] = {
                "ext": sig.ext, "name": sig.name, "category": sig.category,
                "headers": [], "length": "estimate"}
            out.append(row)
        head = sig.head.text()
        if sig.header_offset:
            head = "@%d: %s" % (sig.header_offset, head)
        row["headers"].append(head)
        how = ("structure" if sig.sizer else
               "footer" if sig.foot else "estimate")
        rank = ("estimate", "footer", "structure")
        if rank.index(how) > rank.index(row["length"]):
            row["length"] = how
    order = {c: i for i, c in enumerate(CATEGORIES)}
    out.sort(key=lambda r: order.get(r["category"], len(order)))
    return out

CUSTOM_LIMITS = {
    "name": 60, "ext": 10, "pattern": 64, "header_offset": 4096,
    "footer_extra": 65536, "min_size": 512, "max_size": MAX_CARVE,
    "count": 50,
}
_EXT = re.compile(r"^[A-Za-z0-9]{1,10}$")
_ID = re.compile(r"^[A-Za-z0-9_-]{1,40}$")

def _int(value, key, lo, hi):
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise SignatureError(key, lo, hi)
    if isinstance(value, float) and value != n or not lo <= n <= hi:
        raise SignatureError(key, lo, hi)
    return n

def custom_signature(spec):
    if not isinstance(spec, dict):
        raise SignatureError("not_a_signature")
    name = str(spec.get("name") or "").strip()
    if not name or len(name) > CUSTOM_LIMITS["name"] or \
            any(ord(c) < 32 for c in name):
        raise SignatureError("bad_name", CUSTOM_LIMITS["name"])
    ext = str(spec.get("ext") or "").strip().lstrip(".")
    if not _EXT.match(ext):
        raise SignatureError("bad_ext", CUSTOM_LIMITS["ext"])
    ext = ext.lower()

    head = Pattern(str(spec.get("header") or ""))
    if len(head) > CUSTOM_LIMITS["pattern"]:
        raise SignatureError("header_too_long", CUSTOM_LIMITS["pattern"])
    if sum(1 for b in head.items if b is not None) < 2:
        raise SignatureError("header_too_short")
    if head.items[0] is None:
        raise SignatureError("header_starts_wild")

    foot = None
    footer_text = str(spec.get("footer") or "").strip()
    if footer_text:
        foot = Pattern(footer_text)
        if len(foot) > CUSTOM_LIMITS["pattern"]:
            raise SignatureError("footer_too_long", CUSTOM_LIMITS["pattern"])
        if foot.items[0] is None or foot.items[-1] is None:
            raise SignatureError("footer_ends_wild")

    header_offset = _int(spec.get("header_offset", 0), "bad_header_offset",
                         0, CUSTOM_LIMITS["header_offset"])
    footer_extra = _int(spec.get("footer_extra", 0), "bad_footer_extra",
                        0, CUSTOM_LIMITS["footer_extra"])
    max_size = _int(spec.get("max_size", 1 << 20), "bad_max_size",
                    CUSTOM_LIMITS["min_size"], CUSTOM_LIMITS["max_size"])
    footer_mode = spec.get("footer_mode", "first")
    if footer_mode not in ("first", "last"):
        raise SignatureError("bad_choice", "footer_mode")
    missing = spec.get("missing_footer", "discard")
    if missing not in ("discard", "estimate"):
        raise SignatureError("bad_choice", "missing_footer")

    canon = {
        "name": name, "ext": ext, "header": head.text(),
        "header_offset": header_offset,
        "footer": foot.text() if foot else "",
        "footer_mode": footer_mode, "footer_extra": footer_extra,
        "missing_footer": missing, "max_size": max_size,
        "stop_at_allocated": bool(spec.get("stop_at_allocated", True)),
        "stop_at_zeros": bool(spec.get("stop_at_zeros", False)),
    }
    sid = spec.get("id")
    if sid is not None:
        if not isinstance(sid, str) or not _ID.match(sid):
            raise SignatureError("bad_id")
        canon["id"] = sid
    if "on" in spec:
        canon["on"] = bool(spec["on"])

    sig = Signature(ext, name, head.items, foot.items if foot else None,
                    max_size=max_size, header_offset=header_offset,
                    default_size=max_size, category="custom",
                    footer_last=footer_mode == "last",
                    footer_extra=footer_extra, missing_footer=missing,
                    stop_at_allocated=canon["stop_at_allocated"],
                    stop_at_zeros=canon["stop_at_zeros"], custom=True)
    return sig, canon

def signatures_for(extensions=None, custom=None):
    sigs = [s for s in SIGNATURES
            if extensions is None or s.ext in extensions]
    canon = []
    for spec in custom or []:
        sig, c = custom_signature(spec)
        sigs.append(sig)
        canon.append(c)
    return sigs, canon

def _merge(intervals):
    if not intervals:
        return []
    intervals = sorted(intervals)
    out = [list(intervals[0])]
    for s, e in intervals[1:]:
        if s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out

def _excluded(pos, merged):
    lo, hi = 0, len(merged)
    while lo < hi:
        mid = (lo + hi) // 2
        s, e = merged[mid]
        if pos < s:
            hi = mid
        elif pos >= e:
            lo = mid + 1
        else:
            return True
    return False

def _next_excluded_index(pos, merged):
    lo, hi = 0, len(merged)
    while lo < hi:
        mid = (lo + hi) // 2
        if merged[mid][0] <= pos:
            lo = mid + 1
        else:
            hi = mid
    return lo if lo < len(merged) else None

def _next_excluded(pos, merged):
    i = _next_excluded_index(pos, merged)
    return merged[i][0] if i is not None else None

def _single_gap_within(lo, hi, merged):
    """The one excluded (allocated) extent strictly inside (lo, hi), or
    None if there isn't exactly one. A second fragmented file recovered
    from unallocated space is often separated from its header by exactly
    one still-allocated extent -- other data that landed in the space
    between the two once-contiguous fragments. More than one such extent
    means more than two fragments, which this carving pass does not
    attempt."""
    if not merged:
        return None
    i = _next_excluded_index(lo, merged)
    if i is None:
        return None
    gap = merged[i]
    if gap[0] <= lo or gap[1] >= hi:
        return None
    if i + 1 < len(merged) and merged[i + 1][0] < hi:
        return None
    return gap

def _bifragment(sig, abs_pos, length, merged):
    """Splits a footer-confirmed hit around a single allocated extent that
    falls between its header and footer, so the reconstructed file can skip
    that extent's bytes instead of splicing unrelated data into the middle
    of it. Returns [[frag1_offset, frag1_length], [frag2_offset,
    frag2_length]], or None if there is no such gap, or the resulting pieces
    are too small to plausibly hold the header or footer they must carry."""
    gap = _single_gap_within(abs_pos, abs_pos + length, merged)
    if gap is None:
        return None
    frag1_len = gap[0] - abs_pos
    frag2_off = gap[1]
    frag2_len = (abs_pos + length) - gap[1]
    if frag1_len < sig.header_offset + len(sig.head) or \
            frag2_len < len(sig.foot):
        return None
    return [[abs_pos, frag1_len], [frag2_off, frag2_len]]

def _first_empty_sector(buf, size):
    zero = bytes(size)
    i = size
    while True:
        j = buf.find(zero, i)
        if j < 0:
            return None
        k = -(-j // size) * size
        if k + size <= len(buf) and buf[k:k + size] == zero:
            return k
        i = max(j + 1, k + 1)

def carve(source, start=0, end=None, extensions=None, exclude=None,
          alignment=512, align_base=0, window=8 << 20, progress=None,
          max_hits=20000, verify_entropy=True, signatures=None):
    end = end if end is not None else source.size
    sigs = signatures if signatures is not None else [
        s for s in SIGNATURES if extensions is None or s.ext in extensions]
    merged = _merge(exclude or [])
    sector = alignment if alignment > 1 else 512
    results = []
    pos = start
    total = max(1, end - start)
    overlap = max(4096, max([len(s.head) + s.header_offset for s in sigs] or [0]))

    while pos < end and len(results) < max_hits:
        buf = source.read_at(pos, min(window, end - pos))
        if not buf:
            break
        last = pos + len(buf) >= end
        limit = len(buf) if last else max(1, len(buf) - overlap)
        for sig in sigs:
            i = 0
            while True:
                i = sig.head.find(buf, i)
                if i < 0 or i >= limit:
                    break
                abs_pos = pos + i - sig.header_offset
                i += 1
                if abs_pos < start or abs_pos >= end or abs_pos < 0:
                    continue
                if alignment > 1 and (abs_pos - align_base) % alignment:
                    continue
                if merged and _excluded(abs_pos, merged):
                    continue
                length, method = _determine_length(
                    source, sig, abs_pos, end, merged=merged, sector=sector)
                if not length:
                    continue
                fragments = None
                if method == "footer" and merged:
                    fragments = _bifragment(sig, abs_pos, length, merged)
                head_len = fragments[0][1] if fragments else length
                head = source.read_at(abs_pos, min(512, head_len))
                hit = {
                    "offset": abs_pos, "length": length, "ext": sig.ext,
                    "type": sig.name,
                    "method": method,
                    "bounded": method in BOUNDED,
                    "aligned": alignment > 1,
                    "entropy": round(entropy_mod.of(head), 3) if verify_entropy else None,
                    "id": "carve:%d:%s" % (abs_pos, sig.ext),
                }
                if fragments:
                    gap_off = fragments[0][0] + fragments[0][1]
                    hit["fragments"] = fragments
                    hit["gap"] = {"offset": gap_off,
                                 "length": fragments[1][0] - gap_off}
                if sig.custom:
                    hit["custom"] = True
                    hit["id"] = "carve:%d:%s:custom" % (abs_pos, sig.ext)
                results.append(hit)
                if len(results) >= max_hits:
                    break
            if len(results) >= max_hits:
                break
        if pos + len(buf) >= end:
            pos = end
        else:
            pos += max(1, len(buf) - overlap)
        if progress:
            progress(min(1.0, (pos - start) / total), results)

    results.sort(key=lambda r: (r["offset"], -r["length"]))
    return _dedupe(results)

def _determine_length(source, sig, abs_pos, end, merged=None, sector=512):
    cap = min(sig.max_size, end - abs_pos, MAX_CARVE)
    if cap <= 0:
        return 0, "none"

    probe_cache = []

    def read_probe():
        if not probe_cache:
            buf = source.read_at(abs_pos, min(cap, PROBE))
            nxt = sig.head.find(buf, sig.header_offset + 1)
            nxt = nxt - sig.header_offset if nxt >= 0 else -1
            if nxt > 0:
                probe_cache.append((buf[:nxt], True))
            else:
                probe_cache.append((buf, False))
        return probe_cache[0]

    if sig.sizer:
        probe, _ = read_probe()
        try:
            n = sig.sizer(probe)
        except Exception:
            n = None
        if n and 0 < n <= cap:
            return n, "structure"
    if sig.foot:
        probe, _ = read_probe()
        after = sig.header_offset + len(sig.head)
        at = (sig.foot.rfind(probe, after) if sig.footer_last
              else sig.foot.find(probe, after))
        if at > 0:
            n = min(at + len(sig.foot) + sig.footer_extra, cap)
            return n, "footer"
        if sig.missing_footer == "discard" or sig.strict:
            return 0, "none"
    if sig.strict:
        return 0, "none"
    return _estimate(source, sig, abs_pos, cap, read_probe, merged, sector)

def _estimate(source, sig, abs_pos, cap, read_probe, merged, sector):
    bounds = [(min(cap, sig.default_size), "limit")]
    probe, cut = read_probe()
    if cut:
        bounds.append((len(probe), "next_header"))
    if merged and sig.stop_at_allocated:
        nxt = _next_excluded(abs_pos, merged)
        if nxt is not None:
            bounds.append((nxt - abs_pos, "allocated"))
    if sig.stop_at_zeros:
        z = _first_empty_sector(probe, sector)
        if z is not None:
            bounds.append((z, "empty_sector"))
    rank = ("next_header", "allocated", "empty_sector", "limit")
    n, method = min(bounds, key=lambda b: (b[0], rank.index(b[1])))
    return (n, method) if n > 0 else (0, "none")

def _dedupe(results):
    out = []
    for r in results:
        contained = False
        for prev in reversed(out[-64:]):
            if not prev.get("bounded"):
                continue
            if prev["offset"] <= r["offset"] and \
                    r["offset"] + r["length"] <= prev["offset"] + prev["length"] and \
                    prev["length"] > r["length"]:
                contained = True
                break
        if not contained:
            out.append(r)
    return out
