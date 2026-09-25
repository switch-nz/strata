"""Parse browser disk-cache entry files found during the volume walk.

Chromium Simple Cache entries (``<16-hex-hash>_0``) and Firefox cache2
entries (``cache2/entries/<2hex>/<2hex>/<40hex>``) are self-describing;
this module decodes the URL, HTTP status and timestamps straight out of
each entry file. The Chromium index (``index-dir/the-real-index``) and
the legacy blockfile backend (``data_0``..``data_4``, ``f_XXXXXX``) are
detected and reported but never parsed.
"""

import re
import struct

from . import browser

SIMPLE_INITIAL_MAGIC = 0xFCFB6D1BA7725C30
SIMPLE_FINAL_MAGIC = 0xF4FA6F45970D41D8
_SIMPLE_HDR = struct.Struct("<QIIII")   # SimpleFileHeader, 24 B
_SIMPLE_EOF = struct.Struct("<QIIII")   # SimpleFileEOF, 24 B
FLAG_HAS_CRC32 = 1 << 0
FLAG_HAS_KEY_SHA256 = 1 << 1

CHUNK_SIZE = 262144                     # netwerk/cache2/CacheFileChunk.h

CHROMIUM_ENTRY_RE = re.compile(r"^[0-9a-f]{16}_0$")
CACHE2_ENTRY_RE = re.compile(r"^[0-9a-f]{40}$")
BLOCKFILE_RE = re.compile(r"^(?:f_[0-9a-f]{6}|data_[0-4])$")
_URL_SCHEME_RE = re.compile(rb":(?=(?:https?|ftp|file|wss?)://)")
_CACHE2_LIMIT = 1 << 20

READ_CAP = 16 << 20


def classify(e):
    """Classify a walked entry as a cache artefact, or None.

    Decides from name + path only, before any file read.
    """
    name = (e.get("name") or "").lower()
    path = (e.get("path") or "").lower()
    if "code cache" in path.replace("\\", "/").split("/"):
        # Chromium's V8 compiled-code cache uses the same on-disk formats
        # as the HTTP cache but holds no web content, only script bytecode
        # keyed by script URL.
        return None
    if name == "the-real-index" or "index-dir/the-real-index" in path:
        return "index"
    if "cache" in path:
        if BLOCKFILE_RE.match(name):
            return "blockfile"
    if CHROMIUM_ENTRY_RE.match(name):
        return "chromium"
    if CACHE2_ENTRY_RE.match(name) and "cache2" in path:
        return "firefox"
    return None


def _split_http_headers(blob):
    """(status, content_type, note) from a stream holding an HTTP head."""
    pos = blob.rfind(b"HTTP/")
    if pos < 0:
        return None, None, "no HTTP headers in stream 0"
    head = blob[pos:]
    end = head.find(b"\r\n\r\n")
    if end >= 0:
        head = head[:end]
    status = None
    content_type = None
    lines = head.decode("utf-8", "replace").split("\r\n")
    for i, line in enumerate(lines):
        if i == 0:
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
            continue
        k, _, v = line.partition(":")
        if k.lower() == "content-type":
            content_type = v.strip()
    return status, content_type, None


_KEY_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)


def _chromium_key_url(key):
    """The resource URL in a Chromium HTTP cache key, as Chromium's own
    HttpCache::GetResourceURLFromHttpCacheKey reads it. The key is
    ``credential_key/upload_id/[isolation_key]url``; an entry stored under
    a partitioned cache has an isolation key that starts ``_dk_`` and ends
    at the last space (a URL never holds an unescaped space). Keys that
    are not in that form (a bare URL from an older cache, or the numeric
    ids used by the service worker script cache) give None."""
    if re.match(r"^(?:https?|ftp|file|wss?)://", key):
        return key
    first = key.find("/")
    second = key.find("/", first + 1) if first >= 0 else -1
    if second < 0:
        return None
    rest = key[second + 1:]
    if rest.startswith("_dk_"):
        space = rest.rfind(" ")
        if space < 0:
            return None
        rest = rest[space + 1:]
    return rest if _KEY_URL_RE.match(rest) else None


def parse_simple_entry(data):
    """Chromium Simple Cache ``_0`` stream -> row or None.

    Layout: SimpleFileHeader(24) | key | stream-1 data |
    SimpleFileEOF(24) | stream-0 data | [key SHA256 (32)] |
    SimpleFileEOF(24) trailing. Sizes are little-endian; the final
    EOF's flags say whether a key SHA256 sits before it.
    """
    if len(data) < _SIMPLE_HDR.size:
        return None
    _, version, key_length, _, _ = _SIMPLE_HDR.unpack_from(data, 0)
    magic = struct.unpack_from("<Q", data, 0)[0]
    if magic != SIMPLE_INITIAL_MAGIC:
        return None
    head_end = _SIMPLE_HDR.size + key_length
    if len(data) < head_end:
        return None
    key = data[_SIMPLE_HDR.size:head_end].decode("utf-8", "replace")
    if len(data) < _SIMPLE_EOF.size:
        return None
    final_magic, flags, _, stream0_size, _ = _SIMPLE_EOF.unpack_from(
        data, len(data) - _SIMPLE_EOF.size)
    if final_magic != SIMPLE_FINAL_MAGIC:
        return None
    block_end = (len(data) - _SIMPLE_EOF.size - 32
                 if flags & FLAG_HAS_KEY_SHA256
                 else len(data) - _SIMPLE_EOF.size)
    if stream0_size > block_end - head_end:
        return None
    stream0 = data[block_end - stream0_size:block_end] if stream0_size else b""
    status, content_type, note = _split_http_headers(stream0)
    url = _chromium_key_url(key)
    if url is None:
        note = "key has no URL: %s" % key
    return {
        "url": url, "key": key, "status": status,
        "content_type": content_type,
        "last_modified": None, "last_fetched": None,
        "fetched_count": None, "source": "chromium", "note": note,
    }


def _unix_seconds(v):
    if not v:
        return None
    import datetime
    try:
        return (browser.UNIX_EPOCH
                + datetime.timedelta(seconds=int(v))).isoformat() + "Z"
    except (OverflowError, ValueError, TypeError):
        return None


def parse_cache2_entry(data):
    """Firefox cache2 entry -> row or None.

    Trailing 4 B big-endian uint32 is the metadata-block offset. The
    metadata block holds a CityHash-based metadata hash (never verified
    — damaged evidence must still parse), one uint16 chunk hash per
    256 KiB chunk, a big-endian CacheFileMetadataHeader (32 B for
    version >= 2, 28 B for version 1), the key, then NUL-separated
    ``key\\0value\\0`` element pairs.
    """
    if len(data) < 40:
        return None
    meta_offset = struct.unpack_from(">I", data, len(data) - 4)[0]
    if meta_offset <= 0 or len(data) - 4 - meta_offset < 36:
        return None
    block = data[meta_offset:len(data) - 4]
    hash_count = -(-meta_offset // CHUNK_SIZE)
    hdr_at = 4 + hash_count * 2
    if hdr_at + 32 > len(block):
        return None
    (version, fetch_count, last_fetched, last_modified, _frecency,
     _expiration, key_size, flags) = struct.unpack_from(">8I", block, hdr_at)
    if version == 1:
        # v1 header has no flags field: 28 B, seven uint32s.
        (version, fetch_count, last_fetched, last_modified, _frecency,
         _expiration, key_size) = struct.unpack_from(">7I", block, hdr_at)
        flags = 0
    elif version not in (2, 3):
        return None
    hdr_size = 32 if version >= 2 else 28
    key_at = hdr_at + hdr_size
    if key_size > len(block) - key_at - 1:
        return None
    key = block[key_at:key_at + key_size]
    if block[key_at + key_size:key_at + key_size + 1] != b"\0":
        return None
    rest = block[key_at + key_size + 1:]
    if not rest or not rest.endswith(b"\0") or rest.count(b"\0") % 2:
        return None
    elements = {}
    pos = 0
    while pos < len(rest):
        kend = rest.find(b"\0", pos)
        if kend < 0:
            break
        ek = rest[pos:kend]
        vend = rest.find(b"\0", kend + 1)
        if vend < 0:
            break
        elements[ek.decode("utf-8", "replace")] = rest[
            kend + 1:vend].decode("utf-8", "replace")
        pos = vend + 1
    head = elements.get("response-head")
    if head is not None:
        status, content_type, note = _split_http_headers(
            head.encode("utf-8", "replace"))
    else:
        status, content_type, note = None, None, None
    key_s = key.decode("utf-8", "replace")
    m = _URL_SCHEME_RE.search(key)
    if key.startswith((b"https://", b"http://", b"ftp://", b"file://",
                       b"ws://", b"wss://")):
        url = key_s
    elif m:
        url = key_s[m.start() + 1:]
    elif key_s.startswith(":"):
        url, note = key_s[1:], (note or "key has no URL")
    else:
        url, note = None, "key has no URL: %s" % key_s
    return {
        "url": url, "key": key_s, "status": status,
        "content_type": content_type,
        "last_modified": _unix_seconds(last_modified),
        "last_fetched": _unix_seconds(last_fetched),
        "fetched_count": fetch_count, "source": "firefox", "note": note,
    }


def parse_entry(data, entry):
    kind = classify(entry)
    parse = (parse_simple_entry if kind == "chromium"
             else parse_cache2_entry if kind == "firefox" else None)
    row = parse(data) if parse else None
    if row is None:
        return None
    row["product"] = browser.product_from_path(entry.get("path"))
    row["path"] = entry.get("path")
    row["size"] = entry.get("size")
    return row


def collect(fs, entries, progress=None, limit=20000):
    """Parse cache entry files out of an already-collected walk.

    Returns {"rows", "count", "skipped", "findings", "blockfile",
    "index_present"}; never raises.
    """
    rows, findings = [], []
    parsed = skipped = blockfile = 0
    index_present = False
    total = max(1, len(entries))
    for i, e in enumerate(entries):
        if progress is not None and i % 64 == 0:
            progress(i / total)
        kind = classify(e)
        if kind == "blockfile":
            blockfile += 1
            continue
        if kind == "index":
            index_present = True
            continue
        if kind not in ("chromium", "firefox"):
            continue
        if (e.get("size") or 0) > READ_CAP:
            skipped += 1
            continue
        if len(rows) >= limit:
            skipped += 1
            continue
        try:
            row = parse_entry(fs.read_file(e, READ_CAP), e)
        except Exception:
            row = None
        if row is None:
            skipped += 1
        else:
            rows.append(row)
            parsed += 1
    if blockfile:
        findings.append(
            "Legacy Chromium blockfile cache found (%d file%s under a "
            "Cache data directory); its entries were not parsed."
            % (blockfile, "" if blockfile == 1 else "s"))
    if index_present:
        findings.append(
            "A Chromium cache index (index-dir/the-real-index) is present; "
            "entry files were read directly and the index was not parsed.")
    if skipped:
        findings.append(
            "%d cache entry file%s could not be read or parsed."
            % (skipped, "" if skipped == 1 else "s"))
    return {"rows": rows, "count": parsed, "skipped": skipped,
            "findings": findings, "blockfile": blockfile,
            "index_present": index_present}